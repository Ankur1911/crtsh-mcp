"""Task-shaped tools built on crt.sh identity searches.

Each function takes a client and plain arguments and returns a JSON-serialisable value. Raw rows
are trimmed: SAN lists are filtered to the names that belong to the queried domain, issuers are
shortened, and everything is capped so one large domain cannot flood a model's context.
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from .client import CrtShClient, CrtShError, clean_domain

MAX_NAMES_PER_CERT = 8


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        return None


def short_issuer(issuer_name: str | None) -> str:
    """'C=US, O=Let's Encrypt, CN=R11' -> "Let's Encrypt (R11)"."""
    if not issuer_name:
        return "unknown"
    org = re.search(r"(?:^|,\s*)O=([^,]+)", issuer_name)
    cn = re.search(r"(?:^|,\s*)CN=([^,]+)", issuer_name)
    if org and cn:
        return f"{org.group(1).strip()} ({cn.group(1).strip()})"
    return (org or cn).group(1).strip() if (org or cn) else issuer_name


def _day(ts: datetime | None) -> str | None:
    return ts.strftime("%Y-%m-%d") if ts else None


def _in_domain(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def _names(row: dict[str, Any], domain: str | None = None) -> list[str]:
    raw = (row.get("name_value") or row.get("common_name") or "").lower().split("\n")
    seen: dict[str, None] = {}
    for n in raw:
        n = n.strip()
        if n and (domain is None or _in_domain(n.removeprefix("*."), domain)):
            seen[n] = None
    return list(seen)


def _cert_url(row: dict[str, Any]) -> str:
    return f"https://crt.sh/?id={row.get('id')}"


def _compact(row: dict[str, Any], domain: str, now: datetime) -> dict[str, Any]:
    names = _names(row, domain)
    nb, na = parse_ts(row.get("not_before")), parse_ts(row.get("not_after"))
    out: dict[str, Any] = {
        "id": row.get("id"),
        "url": _cert_url(row),
        "common_name": row.get("common_name"),
        "names": names[:MAX_NAMES_PER_CERT],
        "issuer": short_issuer(row.get("issuer_name")),
        "not_before": _day(nb),
        "not_after": _day(na),
        "valid_now": bool(nb and na and nb <= now <= na),
    }
    if len(names) > MAX_NAMES_PER_CERT:
        out["more_names"] = len(names) - MAX_NAMES_PER_CERT
    return out


async def _subdomain_rows(client: CrtShClient, domain: str, include_expired: bool) -> list[dict[str, Any]]:
    return await client.search(f"%.{domain}", exclude_expired=not include_expired)


async def find_subdomains(
    client: CrtShClient,
    domain: str,
    include_expired: bool = False,
    include_wildcards: bool = True,
    limit: int = 200,
    now: datetime | None = None,
) -> dict[str, Any]:
    domain = clean_domain(domain)
    now = now or utcnow()
    rows = await _subdomain_rows(client, domain, include_expired)
    info: dict[str, dict[str, Any]] = {}
    wildcards: dict[str, None] = {}
    for row in rows:
        nb, na = parse_ts(row.get("not_before")), parse_ts(row.get("not_after"))
        for name in _names(row, domain):
            if name.startswith("*."):
                wildcards[name] = None
                continue
            e = info.setdefault(name, {"certs": 0, "first_seen": None, "last_expires": None, "valid_now": False})
            e["certs"] += 1
            if nb and (e["first_seen"] is None or nb < e["first_seen"]):
                e["first_seen"] = nb
            if na and (e["last_expires"] is None or na > e["last_expires"]):
                e["last_expires"] = na
            if nb and na and nb <= now <= na:
                e["valid_now"] = True
    names = sorted(info, key=lambda n: (n.count("."), n))
    listed = [
        {"name": n, "certs": info[n]["certs"], "first_seen": _day(info[n]["first_seen"]),
         "last_expires": _day(info[n]["last_expires"]), "valid_now": info[n]["valid_now"]}
        for n in names[:limit]
    ]
    out: dict[str, Any] = {
        "domain": domain,
        "scope": "all certificates, including expired" if include_expired else "unexpired certificates only",
        "certificates_scanned": len(rows),
        "unique_names": len(info),
        "subdomains": listed,
    }
    if len(info) > limit:
        out["truncated"] = f"showing {limit} of {len(info)} names; raise limit or search a narrower subdomain"
    if include_wildcards:
        out["wildcards"] = list(wildcards)[:50]
    else:
        out["wildcard_count"] = len(wildcards)
    return out


async def certificate_status(
    client: CrtShClient, domain: str, within_days: int = 30, now: datetime | None = None
) -> dict[str, Any]:
    domain = clean_domain(domain)
    now = now or utcnow()
    horizon = now + timedelta(days=within_days)
    rows = await _subdomain_rows(client, domain, include_expired=False)
    valid = []
    for row in rows:
        nb, na = parse_ts(row.get("not_before")), parse_ts(row.get("not_after"))
        if nb and na and nb <= now <= na:
            valid.append((row, nb, na))
    if not valid:
        return {
            "domain": domain,
            "valid_certificates": 0,
            "note": "No currently valid certificates are logged for this domain or its subdomains.",
        }
    best: dict[str, tuple[datetime, dict[str, Any]]] = {}
    issuers: Counter[str] = Counter()
    wildcards: dict[str, None] = {}
    for row, _nb, na in valid:
        issuers[short_issuer(row.get("issuer_name"))] += 1
        for name in _names(row, domain):
            if name.startswith("*."):
                wildcards[name] = None
            if name not in best or na > best[name][0]:
                best[name] = (na, row)
    at_risk = sorted(
        ((n, na, row) for n, (na, row) in best.items() if na <= horizon), key=lambda t: (t[1], t[0])
    )
    soonest = min(valid, key=lambda t: t[2])
    return {
        "domain": domain,
        "valid_certificates": len(valid),
        "names_covered": len(best),
        "issuers": dict(issuers.most_common()),
        "wildcards": list(wildcards)[:50],
        "soonest_expiry": {
            "date": _day(soonest[2]), "days_left": (soonest[2] - now).days, "url": _cert_url(soonest[0]),
        },
        f"names_expiring_within_{within_days}_days": [
            {"name": n, "expires": _day(na), "days_left": (na - now).days, "url": _cert_url(row)}
            for n, na, row in at_risk[:100]
        ],
        "note": "A name is listed only if no longer-lived valid certificate covers it, so renewed names are not flagged.",
    }


async def list_certificates(
    client: CrtShClient,
    domain: str,
    match: str = "subdomains",
    include_expired: bool = False,
    issuer: str | None = None,
    limit: int = 20,
    now: datetime | None = None,
) -> dict[str, Any]:
    domain = clean_domain(domain)
    now = now or utcnow()
    query = domain if match == "exact" else f"%.{domain}"
    rows = await client.search(query, exclude_expired=not include_expired)
    if issuer:
        rows = [r for r in rows if issuer.lower() in (r.get("issuer_name") or "").lower()]
    if match == "exact":
        rows = [r for r in rows if domain in _names(r) or f"*.{domain}" in _names(r)]
    rows = sorted(rows, key=lambda r: r.get("not_before") or "", reverse=True)
    out: dict[str, Any] = {
        "domain": domain,
        "match": match,
        "total": len(rows),
        "certificates": [_compact(r, domain, now) for r in rows[:limit]],
    }
    if len(rows) > limit:
        out["truncated"] = f"showing newest {limit} of {len(rows)}; raise limit or add an issuer filter"
    return out


async def recent_issuance(
    client: CrtShClient, domain: str, days: int = 30, now: datetime | None = None
) -> dict[str, Any]:
    domain = clean_domain(domain)
    now = now or utcnow()
    cutoff = now - timedelta(days=days)
    rows = await _subdomain_rows(client, domain, include_expired=False)
    recent, older = [], []
    for row in rows:
        nb = parse_ts(row.get("not_before"))
        if nb is None:
            continue
        (recent if nb >= cutoff else older).append(row)
    recent.sort(key=lambda r: r.get("not_before") or "", reverse=True)
    recent_issuers = Counter(short_issuer(r.get("issuer_name")) for r in recent)
    older_issuers = {short_issuer(r.get("issuer_name")) for r in older}
    return {
        "domain": domain,
        "window_days": days,
        "issued_in_window": len(recent),
        "issuers": dict(recent_issuers.most_common()),
        "issuers_not_seen_on_older_unexpired_certs": sorted(set(recent_issuers) - older_issuers),
        "certificates": [_compact(r, domain, now) for r in recent[:50]],
        "note": "Compared against other unexpired certificates only. Review unfamiliar issuers or names in case of mis-issuance.",
    }
