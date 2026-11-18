# crtsh-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for [crt.sh](https://crt.sh), the free certificate transparency search run by Sectigo. It lets an MCP client enumerate hostnames seen in public TLS certificates, check certificate health and expiry for a domain, and review recent issuance. It needs no API key.

The tools are shaped around questions people actually ask (which hostnames exist, what expires soon, did something unexpected get issued) instead of mirroring the raw search endpoint. Results are de-duplicated, certificate name lists are filtered to the queried domain, issuers are shortened, and output is capped so a large domain cannot flood the client's context.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Ankur1911/crtsh-mcp.git && cd crtsh-mcp
uv sync
uv run crtsh-mcp          # stdio transport
```

Add it to any MCP client that launches stdio servers:

```json
{
  "mcpServers": {
    "crtsh": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/crtsh-mcp", "crtsh-mcp"]
    }
  }
}
```

For HTTP instead of stdio: `MCP_TRANSPORT=streamable-http MCP_HOST=127.0.0.1 MCP_PORT=8000 uv run crtsh-mcp`.

## Tools

All tools are read-only. Every `domain` argument accepts a bare name, a subdomain, or a URL or `*.` form, which is cleaned up.

| Tool | What it returns |
|---|---|
| `find_subdomains` | Hostnames under a domain seen in certificates, de-duplicated, with certificate count, first-seen date, latest expiry and whether a valid certificate exists now. Wildcards are listed separately. |
| `certificate_status` | One-call health check: valid certificate count, issuers in use, wildcards, soonest expiry, and hostnames that lose coverage within N days (names already renewed by a longer-lived certificate are not flagged). |
| `list_certificates` | Certificates newest first, trimmed to id, crt.sh link, names, issuer, validity dates and a valid-now flag. Filter by issuer substring; `match: exact` limits it to one host. |
| `recent_issuance` | Certificates issued in the last N days, count per issuer, and issuers not seen on older unexpired certificates. |

Example (`certificate_status` for `modelcontextprotocol.io`, abridged):

```json
{"domain":"modelcontextprotocol.io","valid_certificates":30,"names_covered":28,
 "issuers":{"Let's Encrypt (YR1)":9,"Google Trust Services (WE1)":6},
 "soonest_expiry":{"date":"2026-11-21","days_left":3,"url":"https://crt.sh/?id=29051995492"},
 "names_expiring_within_45_days":[{"name":"static.modelcontextprotocol.io","expires":"2026-11-23","days_left":4}]}
```

## Configuration

All optional environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `CRTSH_BASE_URL` | `https://crt.sh` | Search endpoint root (for a mirror or proxy) |
| `CRTSH_TIMEOUT` | `90` | Request timeout in seconds |
| `CRTSH_RETRIES` | `2` | Retries on HTTP 429, 502, 503, 504 and timeouts |
| `CRTSH_RETRY_DELAY` | `2` | Base delay in seconds, doubled on each retry |
| `CRTSH_MAX_CHARS` | `20000` | Maximum characters returned per tool call |
| `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT` | `stdio`, `127.0.0.1`, `8000` | Transport settings (`streamable-http` for HTTP) |

## Limits

- crt.sh is a free, shared service with no published SLA. Queries for very large domains (for example a major company's apex domain) often time out or return HTTP 502 even after retries. Query a specific subdomain, and leave expired certificates out (the default), which makes the query much smaller.
- Results are cached in memory for five minutes, so repeated questions about the same domain make one request.
- Only certificates logged to public CT logs appear. Private CAs and unlogged certificates are invisible, and a hostname appearing in a certificate does not prove it currently resolves.
- Dates are UTC day precision; expiry checks use the machine clock.
- `find_subdomains` returns at most 1000 names per call and `list_certificates` at most 100 certificates.
- Single-certificate detail (decoded fields) is not exposed because crt.sh offers no JSON for it; each result includes a `crt.sh` link instead.

## Development

```bash
uv sync
uv run pytest -q          # HTTP is mocked; no network needed
```

## Licence

MIT. Copyright (c) 2026 Ankur Kapuriya. Data comes from crt.sh and the public certificate transparency logs; check crt.sh's terms before heavy automated use.
