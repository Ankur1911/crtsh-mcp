"""MCP server exposing crt.sh certificate transparency search as four task-shaped tools."""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from . import tools
from .client import CrtShClient, CrtShError

Domain = Annotated[
    str,
    Field(description="Registrable domain or subdomain, e.g. example.com or api.example.com. URLs and '*.' prefixes are cleaned up."),
]
MAX_CHARS = 20000
READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=True, idempotent_hint=True)

client = CrtShClient()
mcp = MCPServer(
    "crtsh",
    instructions=(
        "Search public certificate transparency logs through crt.sh. Use find_subdomains to enumerate hostnames "
        "seen in certificates, certificate_status for a one-call health and expiry check, recent_issuance to spot "
        "new or unexpected certificates, and list_certificates for the certificates themselves. crt.sh is a free, "
        "shared service: very large domains can time out, so prefer a specific domain and leave expired certificates out."
    ),
)


def render(data: Any) -> str:
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    limit = int(os.environ.get("CRTSH_MAX_CHARS", MAX_CHARS))
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated: response was {len(text)} characters; use a smaller limit or a narrower domain]"


async def run(coro: Any) -> str:
    try:
        return render(await coro)
    except CrtShError as exc:
        raise ToolError(str(exc)) from exc


@mcp.tool(
    name="find_subdomains",
    description=(
        "List hostnames under a domain that appear in certificate transparency logs, de-duplicated across "
        "certificates, with the number of certificates, first-seen date, latest expiry and whether a valid "
        "certificate exists now. Wildcard entries are reported separately. By default only unexpired certificates "
        "are searched (faster); set include_expired to also find historical hostnames."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def find_subdomains(
    domain: Domain,
    include_expired: Annotated[bool, Field(description="Also search expired certificates (slower, may time out on large domains).")] = False,
    include_wildcards: Annotated[bool, Field(description="List wildcard names such as *.example.com; otherwise only count them.")] = True,
    limit: Annotated[int, Field(description="Maximum hostnames to return.", ge=1, le=1000)] = 200,
) -> str:
    return await run(tools.find_subdomains(client, domain, include_expired, include_wildcards, limit))


@mcp.tool(
    name="certificate_status",
    description=(
        "One-call TLS certificate health check for a domain and its subdomains: how many certificates are valid "
        "now, which issuers are in use, wildcard names, the soonest expiry, and the hostnames that will lose "
        "coverage within the given number of days (names already renewed by a longer-lived certificate are not flagged)."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def certificate_status(
    domain: Domain,
    within_days: Annotated[int, Field(description="Flag hostnames whose best certificate expires within this many days.", ge=1, le=365)] = 30,
) -> str:
    return await run(tools.certificate_status(client, domain, within_days))


@mcp.tool(
    name="list_certificates",
    description=(
        "List logged certificates for a domain, newest first, trimmed to id, crt.sh link, names, issuer, validity "
        "dates and whether valid now. Filter by issuer substring (for example 'Let's Encrypt'). Use match 'exact' "
        "for certificates naming exactly this host, or 'subdomains' (default) for the domain and everything under it."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def list_certificates(
    domain: Domain,
    match: Annotated[Literal["subdomains", "exact"], Field(description="'subdomains' covers the domain and all hosts under it; 'exact' only the named host.")] = "subdomains",
    include_expired: Annotated[bool, Field(description="Include expired certificates (slower).")] = False,
    issuer: Annotated[str | None, Field(description="Case-insensitive substring of the issuer name to keep.")] = None,
    limit: Annotated[int, Field(description="Maximum certificates to return.", ge=1, le=100)] = 20,
) -> str:
    return await run(tools.list_certificates(client, domain, match, include_expired, issuer, limit))


@mcp.tool(
    name="recent_issuance",
    description=(
        "Certificates issued for a domain and its subdomains in the last N days, with a count per issuer and a "
        "list of issuers not seen on older unexpired certificates. Useful for spotting unexpected issuance or a CA change."
    ),
    annotations=READ_ONLY,
    structured_output=False,
)
async def recent_issuance(
    domain: Domain,
    days: Annotated[int, Field(description="Look-back window in days.", ge=1, le=365)] = 30,
) -> str:
    return await run(tools.recent_issuance(client, domain, days))


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=os.environ.get("LOG_LEVEL", "WARNING").upper())
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run("stdio")
    else:
        mcp.run(transport, host=os.environ.get("MCP_HOST", "127.0.0.1"), port=int(os.environ.get("MCP_PORT", "8000")))


if __name__ == "__main__":
    main()
