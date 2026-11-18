import json
from datetime import datetime

import httpx
import pytest
import respx
from mcp import Client

from crtsh_mcp import server, tools
from crtsh_mcp.client import CrtShError, clean_domain

BASE = "https://crt.sh/"
NOW = datetime(2026, 11, 18, 12, 0, 0)
LE = "C=US, O=Let's Encrypt, CN=R11"
GTS = "C=US, O=Google Trust Services, CN=WE1"


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("CRTSH_RETRY_DELAY", "0")
    monkeypatch.delenv("CRTSH_BASE_URL", raising=False)
    monkeypatch.delenv("CRTSH_MAX_CHARS", raising=False)
    server.client.clear_cache()


def row(id, names, nb, na, issuer=LE, cn=None):
    return {
        "issuer_ca_id": 1,
        "issuer_name": issuer,
        "common_name": cn or names[0],
        "name_value": "\n".join(names),
        "id": id,
        "not_before": nb,
        "not_after": na,
        "serial_number": "ab",
        "result_count": len(names),
    }


ROWS = [
    # valid, renewed later by id 3 (same name, longer-lived)
    row(1, ["www.example.com", "example.com"], "2026-09-01T00:00:00", "2026-11-25T00:00:00"),
    row(2, ["api.example.com", "other.org"], "2026-10-01T00:00:00", "2026-12-30T00:00:00"),
    row(3, ["www.example.com", "example.com"], "2026-11-10T00:00:00", "2027-02-08T00:00:00"),
    # expiring in 7 days and not renewed
    row(4, ["old.example.com"], "2026-08-26T00:00:00", "2026-11-25T00:00:00"),
    # wildcard from another issuer, issued within the last 30 days
    row(5, ["*.example.com", "example.com"], "2026-11-05T00:00:00", "2027-02-03T00:00:00", issuer=GTS),
    # already expired (only returned when expired are included)
    row(6, ["legacy.example.com"], "2025-01-01T00:00:00", "2025-04-01T00:00:00"),
]


def mock_search(router, rows=ROWS):
    def handler(request):
        q = dict(request.url.params)
        if q.get("exclude") == "expired":
            keep = [r for r in rows if datetime.fromisoformat(r["not_after"]) >= NOW]
        else:
            keep = rows
        return httpx.Response(200, json=keep)

    return router.get(BASE).mock(side_effect=handler)


async def call(tool, args=None):
    async with Client(server.mcp) as c:
        return await c.call_tool(tool, args or {})


def data(result):
    return json.loads("".join(x.text for x in result.content))


def test_clean_domain():
    assert clean_domain("https://*.Example.COM/path?x=1") == "example.com"
    assert clean_domain("%.api.example.com") == "api.example.com"
    assert clean_domain("user@example.com:443") == "example.com"
    for bad in ["localhost", "bad domain.com", "", "-x.example.com"]:
        with pytest.raises(CrtShError):
            clean_domain(bad)


def test_short_issuer():
    assert tools.short_issuer(LE) == "Let's Encrypt (R11)"
    assert tools.short_issuer("CN=Only Name") == "Only Name"
    assert tools.short_issuer(None) == "unknown"


@respx.mock
async def test_find_subdomains_dedupes_and_filters_foreign_names():
    mock_search(respx)
    out = await tools.find_subdomains(server.client, "example.com", include_expired=False, now=NOW)
    names = {s["name"]: s for s in out["subdomains"]}
    assert set(names) == {"www.example.com", "example.com", "api.example.com", "old.example.com"}
    assert "other.org" not in names
    assert names["www.example.com"]["certs"] == 2
    assert names["www.example.com"]["first_seen"] == "2026-09-01"
    assert names["www.example.com"]["last_expires"] == "2027-02-08"
    assert names["www.example.com"]["valid_now"] is True
    assert out["wildcards"] == ["*.example.com"]
    assert out["certificates_scanned"] == 5
    # apex first (fewest labels), then alphabetical
    assert out["subdomains"][0]["name"] == "example.com"


@respx.mock
async def test_find_subdomains_include_expired_and_limit():
    route = mock_search(respx)
    out = await tools.find_subdomains(server.client, "example.com", include_expired=True, include_wildcards=False, limit=2, now=NOW)
    assert out["unique_names"] == 5
    assert len(out["subdomains"]) == 2 and "truncated" in out
    assert out["wildcard_count"] == 1 and "wildcards" not in out
    params = dict(route.calls.last.request.url.params)
    assert params["q"] == "%.example.com" and "exclude" not in params and params["deduplicate"] == "Y"


@respx.mock
async def test_certificate_status_flags_only_unrenewed_names():
    mock_search(respx)
    out = await tools.certificate_status(server.client, "example.com", within_days=14, now=NOW)
    assert out["valid_certificates"] == 5
    flagged = out["names_expiring_within_14_days"]
    assert [f["name"] for f in flagged] == ["old.example.com"]
    assert flagged[0]["days_left"] == 6
    assert out["soonest_expiry"]["date"] == "2026-11-25"
    assert out["issuers"] == {"Let's Encrypt (R11)": 4, "Google Trust Services (WE1)": 1}
    assert out["wildcards"] == ["*.example.com"]


@respx.mock
async def test_certificate_status_none_valid():
    mock_search(respx, rows=[ROWS[5]])
    out = await tools.certificate_status(server.client, "example.com", now=NOW)
    assert out["valid_certificates"] == 0


@respx.mock
async def test_list_certificates_sorted_trimmed_and_filtered():
    mock_search(respx)
    out = await tools.list_certificates(server.client, "example.com", limit=3, now=NOW)
    assert out["total"] == 5
    assert [c["id"] for c in out["certificates"]] == [3, 5, 2]
    assert out["certificates"][0]["url"] == "https://crt.sh/?id=3"
    assert out["certificates"][2]["names"] == ["api.example.com"]  # other.org dropped
    assert "truncated" in out
    only_gts = await tools.list_certificates(server.client, "example.com", issuer="google", now=NOW)
    assert [c["id"] for c in only_gts["certificates"]] == [5]


@respx.mock
async def test_list_certificates_exact_match_and_long_san_trim():
    many = row(9, [f"h{i}.example.com" for i in range(12)] + ["example.com"], "2026-11-01T00:00:00", "2027-01-30T00:00:00")
    route = mock_search(respx, rows=[many, ROWS[1]])
    out = await tools.list_certificates(server.client, "example.com", match="exact", now=NOW)
    assert dict(route.calls.last.request.url.params)["q"] == "example.com"
    assert [c["id"] for c in out["certificates"]] == [9]
    assert out["certificates"][0]["more_names"] == 13 - tools.MAX_NAMES_PER_CERT


@respx.mock
async def test_recent_issuance_window_and_new_issuer():
    mock_search(respx)
    out = await tools.recent_issuance(server.client, "example.com", days=20, now=NOW)
    assert out["issued_in_window"] == 2  # ids 3 (Nov 10) and 5 (Nov 5)
    assert out["issuers"] == {"Let's Encrypt (R11)": 1, "Google Trust Services (WE1)": 1}
    assert out["issuers_not_seen_on_older_unexpired_certs"] == ["Google Trust Services (WE1)"]
    assert [c["id"] for c in out["certificates"]] == [3, 5]


@respx.mock
async def test_results_are_cached_between_calls():
    route = mock_search(respx)
    await tools.find_subdomains(server.client, "example.com", now=NOW)
    await tools.certificate_status(server.client, "example.com", now=NOW)
    assert route.call_count == 1


@respx.mock
async def test_retries_502_then_succeeds():
    route = respx.get(BASE).mock(side_effect=[httpx.Response(502, text="<html>Bad Gateway</html>"), httpx.Response(200, json=ROWS[:1])])
    out = await tools.find_subdomains(server.client, "example.com", now=NOW)
    assert route.call_count == 2 and out["unique_names"] == 2


@respx.mock
async def test_persistent_502_gives_actionable_error():
    respx.get(BASE).mock(return_value=httpx.Response(502, text="Bad Gateway"))
    with pytest.raises(CrtShError, match="narrower name"):
        await tools.find_subdomains(server.client, "example.com", now=NOW)


@respx.mock
async def test_timeout_and_non_json_errors():
    respx.get(BASE).mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(CrtShError, match="timed out"):
        await tools.find_subdomains(server.client, "example.com", now=NOW)
    server.client.clear_cache()
    respx.get(BASE).mock(return_value=httpx.Response(200, text="<html>maintenance</html>"))
    with pytest.raises(CrtShError, match="non-JSON"):
        await tools.find_subdomains(server.client, "example.com", now=NOW)


@respx.mock
async def test_empty_result_is_not_an_error():
    respx.get(BASE).mock(return_value=httpx.Response(200, json=[]))
    out = await tools.find_subdomains(server.client, "nothing-here.example", now=NOW)
    assert out["unique_names"] == 0 and out["subdomains"] == []


@respx.mock
async def test_mcp_end_to_end_and_error_surface(monkeypatch):
    mock_search(respx)
    async with Client(server.mcp) as c:
        listed = {t.name for t in (await c.list_tools()).tools}
        assert listed == {"find_subdomains", "certificate_status", "list_certificates", "recent_issuance"}
        res = await c.call_tool("find_subdomains", {"domain": "https://Example.com/"})
        assert not res.is_error
        assert json.loads(res.content[0].text)["domain"] == "example.com"
        bad = await c.call_tool("certificate_status", {"domain": "not a domain"})
        assert bad.is_error and "not a valid domain" in bad.content[0].text


@respx.mock
async def test_output_truncation(monkeypatch):
    monkeypatch.setenv("CRTSH_MAX_CHARS", "300")
    mock_search(respx)
    res = await call("list_certificates", {"domain": "example.com"})
    assert "[truncated" in res.content[0].text
