"""Protocol layer — plugin registry, trust gate, supply-chain attestations, MCP host.

Per ADR-002 (MCP plugin protocol — discovery + cosign trust gate +
OAuth/PRM authorization + STDIO four-gate threat model) + ADR-016
(supply-chain controls). Sprint 4 landed the discovery + registration
substrate (PluginRegistry, TrustGate, SupplyChainPipeline). Sprint 5
adds the MCP host (MCPHost, MCPAuthzClient, capability validator,
manifest extractor, transports).

The MCP host modules ship in this package but split across two
boundaries per Sprint-5 R3 P1 doctrine:

1. **Admission-side modules** (``mcp_manifest``, ``mcp_capabilities``,
   ``mcp_authz``) are SDK-free — they import + construct cleanly
   without the ``mcp`` SDK installed (stdlib + httpx + the Sprint-4
   ``OPAEngine`` subprocess). Pack registration of HTTP MCP packs
   (manifest extraction → capability validation → OAuth/PRM auth
   probe) does NOT need the ``mcp`` SDK.

2. **Runtime-side modules** (``mcp_host``,
   ``mcp_transports.StreamableHTTPTransport``) use the official
   ``mcp`` SDK for session wiring. They live in this package but
   call :func:`require_mcp` at construction time. The SDK lives in
   ``[project.optional-dependencies].adapters``; the kernel image
   does NOT install it.

Importing any ``mcp_*`` module MUST succeed regardless of whether
``mcp`` is installed (every SDK reference is lazy/inside-function,
never at module scope; type-only imports use ``TYPE_CHECKING``).
Constructing :class:`MCPHost` or
:class:`StreamableHTTPTransport` on a kernel image raises
:class:`MCPNotAvailableError`.

The ``create_prod_app`` factory's MCP wiring lands across two Sprint-5
tasks:

- **T2 (this commit):** ``create_prod_app`` checks
  :func:`is_mcp_available` once at startup and emits a structured
  log event — ``mcp.sdk_present_at_startup`` (info) on the SDK-
  available branch, ``mcp.host_unavailable_in_image`` (warning) on
  the SDK-missing branch. ``app.state.mcp_host`` is NOT set in T2
  on either branch — T2 only establishes the availability-check
  contract + the structured-warning shape.
- **T9 (later this sprint):** the SDK-available branch is extended
  to construct :class:`MCPHost` and attach it to ``app.state.mcp_host``.
  The SDK-missing branch's structured warning is unchanged. Until T9
  lands, downstream code MUST use ``getattr(app.state, "mcp_host",
  None)`` — the attribute is unset in T2 even on the SDK-available
  path.

Admission-side modules construct cleanly on either branch (no
:func:`require_mcp` gate); they do not depend on whether the
factory chose to wire MCPHost.

``StdioTransport`` methods all raise ``NotImplementedError``; the
class does NOT call :func:`require_mcp` because it doesn't use the SDK
at all (per Sprint-5 R3 P1 doctrine — :func:`require_mcp` belongs
ONLY where the SDK is actually consumed). Sprint 8 lifts the STDIO
launch path with the sandbox primitive; this package gains a
``mcp_stdio_launcher`` module then.

**Important caveat:** "SDK-free at the MCP layer" does NOT mean
"full Sprint-4 signed-pack admission runs on the kernel image."
Sprint-4's admission pipeline (cosign verification + supply-chain
verifiers + OPA-driven policy gates) ships its load-bearing binaries
(cosign, OPA) in the default-adapters image only — the kernel image
carries the Python admission code but cannot complete a real
``register_with_full_attestation_check`` call without those binaries
on PATH. Sprint 5's contribution is "no NEW default-adapters-only
requirement for admission".
"""

from __future__ import annotations

import importlib.util
import logging

logger = logging.getLogger(__name__)


__all__ = [
    "MCPNotAvailableError",
    "is_mcp_available",
    "require_mcp",
]


class MCPNotAvailableError(RuntimeError):
    """Raised when MCP runtime-side code is invoked on a kernel-image deployment.

    Hard-fails so operators see the misconfiguration immediately rather
    than silent degraded behaviour. The kernel image is a valid deploy
    target for governance + audit + the ``/system/*`` read surfaces;
    it can also import + construct the Sprint-5 MCP admission modules
    (``mcp_manifest``, ``mcp_capabilities``, ``mcp_authz``) without the
    ``mcp`` SDK installed (those modules are SDK-free at the import +
    construction boundary).

    What the kernel image CANNOT do, regardless of this error: complete
    a full Sprint-4 signed-pack admission
    (``register_with_full_attestation_check``) — that path subprocess-
    calls cosign + OPA, which Sprint 4 ships in the default-adapters
    image only. The MCP layer's contribution to that boundary is
    "no NEW default-adapters-only requirement"; full end-to-end
    admission of HTTP MCP packs still requires either the
    default-adapters image or an explicitly-documented local fallback
    that brings cosign + OPA into PATH (out of Sprint 5 scope).

    What this error specifically signals: an attempt to construct
    :class:`MCPHost` or :class:`StreamableHTTPTransport` (the only two
    SDK-using classes per Sprint-5 R3 P1 doctrine) on a venv where the
    ``mcp`` SDK is not installed. Use the default-adapters image if
    you need ``MCPHost.call_tool`` / ``list_tools`` to work.
    """


def is_mcp_available() -> bool:
    """Return ``True`` iff the ``mcp`` SDK is importable in the current venv.

    Sprint-5 wiring across two tasks:

    - **T2 (current):** ``create_prod_app`` calls this once at startup
      and emits a structured log event — ``mcp.sdk_present_at_startup``
      (info) on True, ``mcp.host_unavailable_in_image`` (warning) on
      False. ``app.state.mcp_host`` is NOT set in T2 either way.
    - **T9 (later):** the True branch will be extended to construct
      :class:`MCPHost` and attach it to ``app.state.mcp_host``. The
      False branch remains a structured warning.

    Cheap (uses :func:`importlib.util.find_spec` — no actual import);
    safe to call repeatedly at startup.

    Admission-side code does NOT need to call this — manifest
    extraction, capability validation, and OAuth/PRM auth probing all
    import + construct without the SDK installed.
    """
    return importlib.util.find_spec("mcp") is not None


def require_mcp() -> None:
    """Raise :class:`MCPNotAvailableError` if ``mcp`` SDK is not installed.

    **Call this ONLY in classes that genuinely use the SDK at runtime:**

    - ``MCPHost.__init__`` (orchestrator that opens MCP sessions via
      the SDK)
    - ``StreamableHTTPTransport.__init__`` (HTTP transport wraps the
      SDK's HTTP client)

    **Do NOT call this in:**

    - ``MCPAuthzClient.__init__`` — PRM discovery + token acquisition
      use httpx + OAuth/PRM URL conventions (RFC 8707, OAuth 2.1);
      SDK-free.
    - ``mcp_manifest`` module — uses stdlib
      (``Distribution.locate_file`` + ``tomllib``); SDK-free.
    - ``mcp_capabilities`` module — pure-functional dict validation +
      Sprint-4 ``OPAEngine``; SDK-free.
    - ``StdioTransport.__init__`` — every transport method raises
      :class:`NotImplementedError`; the class never references the SDK.

    Per Sprint-5 R3 P1 doctrine: :func:`require_mcp` belongs ONLY
    where the SDK is actually consumed. Over-applying it to
    admission-side modules would break the SDK-free MCP admission
    extension before manifest validation / auth-probing can run.
    (Note: full Sprint-4 signed-pack admission separately depends on
    cosign + OPA which are default-adapters-only — that boundary is
    independent of this gate.)
    """
    if not is_mcp_available():
        raise MCPNotAvailableError(
            "MCP SDK is not installed in this venv. The `mcp` package "
            "ships in the `adapters` optional-deps group; rebuild with "
            "`uv sync --extra adapters` or use the default-adapters "
            "image (which carries the SDK by construction). Operators "
            "running the kernel image get governance + audit + "
            "/system/* read surfaces, and the Sprint-5 MCP admission "
            "modules (mcp_manifest, mcp_capabilities, mcp_authz) "
            "import + construct without this SDK. Full Sprint-4 "
            "signed-pack admission still depends on cosign + OPA "
            "which are default-adapters-only — that is unrelated to "
            "this error. This error specifically signals an attempt "
            "to construct MCPHost or StreamableHTTPTransport "
            "(runtime-only, default-adapters-only)."
        )


#: Documentation only — not consumed by code. The loader API is the
#: :func:`is_mcp_available` / :func:`require_mcp` pair above. This
#: dict is for future Sprint-N extensions that want to tolerate other
#: optional protocol-layer SDKs (A2A in Sprint 6, etc.).
#:
#: Only the runtime-side modules actually depend on ``mcp`` at
#: construction time per Sprint-5 R3 P1 doctrine; admission-side
#: modules (``mcp_manifest``, ``mcp_capabilities``, ``mcp_authz``) are
#: NOT listed here because they are SDK-free in their import +
#: construction paths. Listing them here would mislead future
#: maintainers into adding ``require_mcp()`` to their constructors.
_PROTOCOL_OPTIONAL_DEPS: dict[str, frozenset[str]] = {
    "cognic_agentos.protocol.mcp_transports": frozenset({"mcp"}),
    "cognic_agentos.protocol.mcp_host": frozenset({"mcp"}),
}
