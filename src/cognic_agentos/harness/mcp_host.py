"""MCP host production construction (Sprint 13.8, ADR-002).

The builder consumes the ALREADY-TRUSTED registry candidates (trust is upstream),
maps them to ``MCPServerEntry``, and assembles the host. SDK-free at import — the
MCP classes import cleanly; ``require_mcp()`` fires only when ``build_mcp_host()``
constructs the transport/host, so this module is only CALLED on the SDK-present
lifespan path (``is_mcp_available()``). Production-constructed but DORMANT until a
caller invokes ``call_tool`` (Fork D / the 13.7 honesty pattern).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlparse

from cognic_agentos.protocol.mcp_host import MCPHost, MCPServerEntry
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError,
    PackManifestNotFoundError,
    extract_pack_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    import httpx

    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters.protocols import SecretAdapter
    from cognic_agentos.harness.runtime import Runtime
    from cognic_agentos.protocol.discovery_status import DiscoveryStatusRecorder
    from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

logger = logging.getLogger(__name__)

#: Wave-1 HTTP transport family the host serves. Mapper-local copy of
#: ``mcp_capabilities._HTTP_TRANSPORT_VALUES`` per the test-only drift-detector
#: doctrine (NO runtime cross-import); drift-pinned in the mapper tests.
_MCP_HTTP_SERVED_TRANSPORTS: frozenset[str] = frozenset({"http", "streamable-http"})


class _RegistryCandidates(Protocol):
    """Structural seam — anything exposing the registered-candidate iterator
    (the real ``PluginRegistry`` or a test stub)."""

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]: ...


def _read_risk_tier(manifest: dict[str, Any]) -> str:
    """``[risk_tier].tier`` (canonical) with the ``[tool.cognic.runtime].risk_tier``
    dual-path fallback; ``""`` when absent (the host's gate normalises)."""
    block = manifest.get("risk_tier")
    if isinstance(block, dict):
        tier = block.get("tier")
        if isinstance(tier, str):
            return tier
    runtime_block = manifest.get("tool", {}).get("cognic", {}).get("runtime", {})
    if isinstance(runtime_block, dict):
        rt = runtime_block.get("risk_tier")
        if isinstance(rt, str):
            return rt
    return ""


def _map_registered_packs_to_servers(registry: _RegistryCandidates) -> dict[str, MCPServerEntry]:
    """Map registered candidates → MCPServerEntry. Two silent-skip arms
    (PackManifestNotFoundError / absent ``[tool.cognic.mcp]`` block) and two
    warn-skip arms (PackManifestMalformedError / present-but-malformed block)."""
    servers: dict[str, MCPServerEntry] = {}
    for cand in registry.iter_registered_pack_candidates():
        try:
            manifest = extract_pack_manifest(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except PackManifestNotFoundError:
            continue  # no manifest → no MCP intent → silent skip (registry doctrine)
        except PackManifestMalformedError:
            logger.warning(
                "mcp.pack_manifest_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        # Tri-state [tool.cognic.mcp] block probe (absent vs present-malformed vs valid).
        tool = manifest.get("tool")
        cognic = tool.get("cognic") if isinstance(tool, dict) else None
        if not isinstance(cognic, dict) or "mcp" not in cognic:
            continue  # ABSENT block → non-MCP → silent skip
        mcp = cognic["mcp"]
        if not isinstance(mcp, dict):
            logger.warning(
                "mcp.pack_mcp_block_malformed",
                extra={
                    "distribution_name": cand.distribution_name,
                    "reason": "mcp block is not a table",
                },
            )
            continue
        server_url = mcp.get("server_url")
        transport_kind = mcp.get("transport")
        if (
            not isinstance(server_url, str)
            or not server_url.strip()
            or not isinstance(transport_kind, str)
        ):
            logger.warning(
                "mcp.pack_mcp_block_malformed",
                extra={
                    "distribution_name": cand.distribution_name,
                    "reason": "missing/invalid server_url or transport",
                },
            )
            continue
        # Mirror the admission SSRF pre-filter (mcp_capabilities.py:466): a
        # non-http/https scheme (file://, gopher://, ...) warns+skips.
        if urlparse(server_url).scheme not in {"http", "https"}:
            logger.warning(
                "mcp.pack_mcp_block_malformed",
                extra={
                    "distribution_name": cand.distribution_name,
                    "reason": "server_url scheme must be http/https",
                },
            )
            continue
        if transport_kind not in _MCP_HTTP_SERVED_TRANSPORTS:
            continue  # stdio / unknown → not served Wave-1 (admission already restricts stdio)
        # scopes is REQUIRED (validate_mcp_manifest: missing → None → not a list →
        # mcp_http_manifest_shape_invalid). Missing/invalid → warn+skip; [] is valid.
        raw_scopes = mcp.get("scopes")
        if not isinstance(raw_scopes, list) or not all(
            isinstance(s, str) and s.strip() for s in raw_scopes
        ):
            logger.warning(
                "mcp.pack_mcp_block_malformed",
                extra={
                    "distribution_name": cand.distribution_name,
                    "reason": "missing/invalid scopes",
                },
            )
            continue
        scopes = tuple(raw_scopes)
        # data_classes flows into the value-free approval envelope — mirror the
        # admission shape gate (_data_classes_shape_violation, mcp_capabilities.py:281):
        # absent/empty is fine; an explicit-but-malformed value (non-list, or any
        # non-string/blank entry) warns+skips rather than being silently dropped.
        dg = manifest.get("data_governance")
        data_classes: tuple[str, ...] = ()
        if isinstance(dg, dict) and "data_classes" in dg:
            raw_dc = dg["data_classes"]
            if not isinstance(raw_dc, list) or not all(
                isinstance(d, str) and d.strip() for d in raw_dc
            ):
                logger.warning(
                    "mcp.pack_mcp_block_malformed",
                    extra={
                        "distribution_name": cand.distribution_name,
                        "reason": "malformed data_classes",
                    },
                )
                continue
            data_classes = tuple(raw_dc)
        entry = MCPServerEntry(
            server_id=cand.distribution_name,
            server_url=server_url,
            transport_kind=transport_kind,  # type: ignore[arg-type]  # validated ∈ served-set
            manifest_scopes=scopes,
            risk_tier=_read_risk_tier(manifest),
            pack_signature_digest=cand.signature_digest or "",
            data_classes=data_classes,
        )
        servers[entry.server_id] = entry
    return servers


def build_mcp_host(
    *,
    registry: _RegistryCandidates,
    runtime: Runtime,
    settings: Settings,
    http_client: httpx.AsyncClient,
    vault_client: SecretAdapter,
    discovery_status_recorder: DiscoveryStatusRecorder | None = None,
) -> MCPHost:
    """Assemble the production MCP host. ``require_mcp()`` fires inside the
    transport ctor — call ONLY on the SDK-present path (``is_mcp_available()``).
    Threads ``runtime.approval_engine`` so the 13.5b2 approval seam is WIRED
    (dormant until a caller invokes ``call_tool``).

    ``discovery_status_recorder`` (PR-1 Slice 2, ADR-002) is the OBSERVATIONAL
    per-(tenant, pack) invoke-time recorder the host writes to; the lifespan
    threads the SAME instance it attaches to ``app.state`` for the
    ``/api/v1/system/plugins`` read surface. ``None`` keeps the host's recording
    a no-op."""
    from cognic_agentos.protocol.mcp_authz import MCPAuthzClient
    from cognic_agentos.protocol.mcp_transports import StreamableHTTPTransport

    authz = MCPAuthzClient(
        settings=settings,
        vault_client=vault_client,
        http_client=http_client,
        audit_store=runtime.audit_store,
        decision_history_store=runtime.decision_history_store,
    )
    transport = StreamableHTTPTransport(authz=authz, settings=settings)
    return MCPHost(
        servers=_map_registered_packs_to_servers(registry),
        transports={"streamable-http": transport},
        authz=authz,
        audit_store=runtime.audit_store,
        decision_history_store=runtime.decision_history_store,
        settings=settings,
        approval_engine=runtime.approval_engine,
        discovery_status_recorder=discovery_status_recorder,
    )
