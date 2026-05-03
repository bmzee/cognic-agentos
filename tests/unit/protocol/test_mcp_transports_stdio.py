"""Sprint-5 T8 — STDIO MCP transport refusal-stub contract tests.

The Decision Lock (Option C, locked at sprint planning) ships:

  - threat model + manifest validation + fail-closed refusal at
    registration in Sprint 5.
  - the actual process-launch path in Sprint 8 with the sandbox
    primitive (see ADR-002 §"Sandbox dependency hard-block" +
    ADR-004).

T8's contribution is **two narrow surfaces**:

  1. ``StdioTransport`` — a pure refusal stub. Default Python
     constructor (no ``__init__`` body, no SDK gating, stores no
     state). Three transport methods (``open_session`` / ``send`` /
     ``close_session``), each an unconditional ``NotImplementedError``
     citing ADR-002 + ADR-004 + the Sprint-8 hand-off.
  2. ``Settings._check_sandbox_availability()`` — fail-fast at
     config-load time when ``runtime_profile == "prod"`` AND
     ``mcp_stdio_enabled = True`` AND
     ``cognic_agentos.sandbox.runtime`` is not importable. Dev /
     staging profiles only emit a warning; prod-with-stdio-disabled
     starts cleanly.

**Where the actual STDIO refusal lives** — NOT in this transport
class. STDIO pack registration refusal lives in T6's
``mcp_capabilities.validate_mcp_manifest`` (returns one of the
``mcp_stdio_*`` closed-enum reasons) + the ``plugin_registry``
admission hook that calls the validator. That gives the registry a
single owner for ``RegistrationOutcome`` creation + audit emission
(per Sprint-4 doctrine; reaffirmed in R2 P2 #4 of the Sprint-5
plan): one writer, one audit row, one closed-enum vocabulary.

This test module's defensive contracts (no ``register`` method, no
audit hook) catch any future drift that re-introduces a refusal-
fabricating method on the transport. The architecture-test gate
(``tests/architecture/test_mcp_stdio_no_subprocess.py``) catches
any future drift that adds process-spawn primitives to the module.
"""

from __future__ import annotations

import importlib.util
import logging
from typing import Any
from unittest.mock import MagicMock

import pytest

from cognic_agentos.core.config import Settings, build_settings_without_env_file

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def transport_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load ``mcp_transports`` with ``require_mcp`` mocked.

    Mirrors the T7 test fixture so the StdioTransport tests run on the
    same harness shape — the mock is unused by ``StdioTransport`` (the
    class deliberately does NOT call ``require_mcp``), but the mock
    keeps tests environment-independent: a venv that happens to lack
    the SDK still constructs the module cleanly.
    """
    from cognic_agentos.protocol import mcp_transports

    monkeypatch.setattr(mcp_transports, "require_mcp", MagicMock())
    return mcp_transports


@pytest.fixture
def settings() -> Settings:
    """Default Settings — runtime_profile=dev, mcp_stdio_enabled=False."""
    return build_settings_without_env_file()


# ---------------------------------------------------------------------------
# StdioTransport — three transport methods MUST all raise NotImplementedError
# ---------------------------------------------------------------------------


class TestStdioTransportTransportMethodsRaiseNotImplemented:
    """Per the Decision Lock: every transport method on
    ``StdioTransport`` is an unconditional ``NotImplementedError``
    raise. There is no condition under which any of these returns a
    session, sends a request, or closes anything — Sprint 5 ships no
    process-launch path at all.

    The error message MUST cite ADR-002 + the Sprint-8 hand-off so
    that an operator who hits this (e.g., via a misconfigured pack
    that somehow bypassed the registry-side refusal) sees the exact
    architectural reason rather than a bare runtime error.
    """

    async def test_open_session_raises_not_implemented(self, transport_module: Any) -> None:
        transport = transport_module.StdioTransport()
        with pytest.raises(NotImplementedError, match="Sprint 8"):
            await transport.open_session(server_url="stdio:///path/to/server", token=MagicMock())

    async def test_send_raises_not_implemented(self, transport_module: Any) -> None:
        transport = transport_module.StdioTransport()
        with pytest.raises(NotImplementedError, match="Sprint 8"):
            await transport.send(MagicMock(), MagicMock())

    async def test_close_session_raises_not_implemented(self, transport_module: Any) -> None:
        transport = transport_module.StdioTransport()
        with pytest.raises(NotImplementedError, match="Sprint 8"):
            await transport.close_session(MagicMock())

    def test_error_messages_cite_adrs(self, transport_module: Any) -> None:
        """All three NotImplementedError messages MUST cite ADR-002
        (STDIO threat model + sandbox-dependency hard-block) so an
        operator sees the architectural reason, not just 'not
        implemented'. The plan specifies ADR-002 + ADR-004 + the
        Sprint-8 hand-off (T15) in the message."""
        import asyncio

        transport = transport_module.StdioTransport()

        async def _collect() -> list[str]:
            messages: list[str] = []
            for coro in (
                transport.open_session(server_url="stdio:///x", token=MagicMock()),
                transport.send(MagicMock(), MagicMock()),
                transport.close_session(MagicMock()),
            ):
                try:
                    await coro
                except NotImplementedError as exc:
                    messages.append(str(exc))
            return messages

        messages = asyncio.run(_collect())
        assert len(messages) == 3
        for msg in messages:
            assert "ADR-002" in msg, f"ADR-002 missing from message: {msg!r}"
            assert "Sprint 8" in msg, f"Sprint 8 hand-off missing from message: {msg!r}"


# ---------------------------------------------------------------------------
# StdioTransport constructor — does NOT call require_mcp (R3 P1 doctrine)
# ---------------------------------------------------------------------------


class TestStdioTransportConstructor:
    """Per Sprint-5 R3 P1 doctrine: ``require_mcp()`` belongs ONLY in
    classes that actually consume the ``mcp`` SDK at runtime.
    ``StdioTransport`` doesn't — every method raises before reaching
    any SDK code path — so the constructor MUST NOT gate on SDK
    availability. The class constructs cleanly on the kernel-image
    venv (no ``mcp`` package installed).
    """

    def test_constructor_takes_no_arguments(self, transport_module: Any) -> None:
        transport = transport_module.StdioTransport()
        assert transport is not None

    def test_constructor_does_not_call_require_mcp(
        self, transport_module: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Even when ``require_mcp`` would raise (kernel-image-equivalent
        venv), constructing ``StdioTransport`` MUST succeed. The
        companion runtime-side test
        ``TestRuntimeRequiresSDK::test_streamable_http_transport_construction_requires_sdk``
        in ``test_optional_dep_loader.py`` covers the inverse contract
        for ``StreamableHTTPTransport``.
        """
        from cognic_agentos.protocol import MCPNotAvailableError

        monkeypatch.setattr(
            transport_module,
            "require_mcp",
            MagicMock(side_effect=MCPNotAvailableError("no mcp sdk in this venv")),
        )
        # Construction MUST succeed despite require_mcp being broken
        transport = transport_module.StdioTransport()
        assert transport is not None
        # And require_mcp MUST NOT have been called
        transport_module.require_mcp.assert_not_called()


# ---------------------------------------------------------------------------
# Defensive: no register method, no audit hook (R2 P2 #4 doctrine)
# ---------------------------------------------------------------------------


class TestStdioTransportRegistryDoctrineBoundaries:
    """The R2 P2 #4 doctrine: ``PluginRegistry.register(...)`` is the
    SINGLE owner of ``RegistrationOutcome`` creation + the closed-
    enum refusal mapping + registry-side audit emission. A transport
    class fabricating its own ``RegistrationOutcome`` would either
    duplicate audit rows OR bypass the closed-enum vocabulary.

    These two defensive tests fail immediately if a future refactor
    re-introduces a refusal-fabricating method on the transport.
    """

    def test_stdio_transport_does_not_have_register_method(self, transport_module: Any) -> None:
        """``StdioTransport`` exposes NO ``register`` method. Pack
        registration is the registry's job; the transport never sees
        a pack object."""
        assert not hasattr(transport_module.StdioTransport, "register"), (
            "StdioTransport must NOT have a `register` method — pack "
            "registration is owned by PluginRegistry per Sprint-4 "
            "doctrine + R2 P2 #4 of the Sprint-5 plan. STDIO refusal "
            "lives in T6's mcp_capabilities.validate_mcp_manifest + "
            "the registry admission hook."
        )

    def test_stdio_transport_does_not_emit_audit_events(self, transport_module: Any) -> None:
        """``StdioTransport`` exposes no audit / event-emission
        surface. The HTTP transport has an ``event_hook`` constructor
        kwarg + ``_emit_event`` / ``_emit_send_error`` /
        ``_emit_send_error_safe`` helpers because it actually opens
        sessions and sends payloads. The STDIO refusal stub has no
        such surface — every method raises before reaching any audit
        path. Registry owns audit emission on STDIO refusal.

        Asserts the absence of the two emission helpers + the
        constructor's ``event_hook`` kwarg, which together would be
        the only paths through which audit events could leak from
        this class.
        """
        cls = transport_module.StdioTransport
        # No emit helpers (the HTTP transport has these; the stub
        # MUST NOT)
        assert not hasattr(cls, "_emit_event"), (
            "StdioTransport must NOT carry the HTTP transport's "
            "audit emission helpers. Registry emits the audit row on "
            "STDIO refusal; the transport stays out of the evidence "
            "path entirely."
        )
        assert not hasattr(cls, "_emit_send_error"), (
            "StdioTransport must NOT carry _emit_send_error — see "
            "the test_stdio_transport_does_not_have_register_method "
            "rationale."
        )
        assert not hasattr(cls, "_emit_send_error_safe"), (
            "StdioTransport must NOT carry _emit_send_error_safe — "
            "see the test_stdio_transport_does_not_have_register_method "
            "rationale."
        )
        # No event_hook attribute on instances
        instance = cls()
        assert not hasattr(instance, "_event_hook"), (
            "StdioTransport instances must NOT carry an _event_hook "
            "attribute. The constructor takes no arguments and stores "
            "no state per Sprint-5 plan."
        )


# ---------------------------------------------------------------------------
# Sandbox-availability check — fail-fast at config-load (Settings)
# ---------------------------------------------------------------------------


class TestSandboxAvailabilityCheck:
    """Sprint-5 plan: at ``Settings`` construction, if
    ``runtime_profile == "prod"`` AND ``mcp_stdio_enabled = True`` AND
    ``cognic_agentos.sandbox.runtime`` is not importable, raise
    ``SandboxNotAvailableError`` immediately. Dev / staging emit a
    warning instead — pack registration is still refused at runtime
    via T6's capability validator regardless.

    The check lives in ``Settings.model_post_init`` so it fires
    once at construction time, NOT per invocation. Failing fast at
    startup is the only safe state when a runtime is misconfigured
    in prod.
    """

    def test_prod_stdio_enabled_no_sandbox_fails_fast(self) -> None:
        """The load-bearing rule: prod + stdio_enabled + no sandbox →
        fail at startup with ``SandboxNotAvailableError``."""
        from cognic_agentos.core.config import SandboxNotAvailableError

        with pytest.raises(SandboxNotAvailableError, match="Sprint 8"):
            build_settings_without_env_file().model_copy(
                update={"runtime_profile": "prod", "mcp_stdio_enabled": True}
            ).model_post_init(None)

    def test_dev_stdio_enabled_no_sandbox_only_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Dev profile with stdio_enabled but no sandbox: emit a
        warning, do NOT fail. Pack registration still refuses at
        runtime via T6's ``mcp_stdio_disabled_in_sprint_5`` capability
        validator regardless of sandbox availability — the dev
        environment can boot for everything else.
        """
        with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.config"):
            settings = build_settings_without_env_file().model_copy(
                update={"runtime_profile": "dev", "mcp_stdio_enabled": True}
            )
            settings.model_post_init(None)

        # A sandbox-related warning was emitted
        sandbox_warnings = [r for r in caplog.records if "sandbox" in r.getMessage().lower()]
        assert sandbox_warnings, (
            "expected at least one sandbox-related WARNING in dev profile "
            "with mcp_stdio_enabled=True and no sandbox.runtime importable"
        )

    def test_prod_stdio_disabled_no_sandbox_starts_clean(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Prod with stdio_enabled=False (the default): no fail, no
        warning. Sandbox availability is irrelevant when the STDIO
        opt-in is off."""
        with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.config"):
            settings = build_settings_without_env_file().model_copy(
                update={"runtime_profile": "prod", "mcp_stdio_enabled": False}
            )
            # MUST NOT raise
            settings.model_post_init(None)

        sandbox_warnings = [r for r in caplog.records if "sandbox" in r.getMessage().lower()]
        assert not sandbox_warnings, (
            "no sandbox-related warning expected when mcp_stdio_enabled=False, "
            f"got: {[r.getMessage() for r in sandbox_warnings]}"
        )

    def test_stage_stdio_enabled_no_sandbox_only_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``stage`` profile behaves like ``dev`` — warn, don't fail.
        Only ``prod`` is fail-fast, because only ``prod`` can actually
        launch processes once Sprint 8 lands."""
        with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.config"):
            settings = build_settings_without_env_file().model_copy(
                update={"runtime_profile": "stage", "mcp_stdio_enabled": True}
            )
            settings.model_post_init(None)

        sandbox_warnings = [r for r in caplog.records if "sandbox" in r.getMessage().lower()]
        assert sandbox_warnings, (
            "expected sandbox-related WARNING in stage profile with "
            "mcp_stdio_enabled=True and no sandbox.runtime importable"
        )

    def test_sandbox_runtime_module_does_not_exist_in_sprint_5(self) -> None:
        """Sprint-5 invariant: the sandbox runtime module simply
        doesn't exist yet — and even the parent package
        ``cognic_agentos.sandbox`` is absent. Sprint 8 lifts. This
        test fails when Sprint 8 lands the module — at which point
        T8's sandbox check transitions from "always raise on
        prod+stdio_enabled" to "only raise if the module exists but
        its readiness probe fails" (separate task; see Sprint 8
        plan).

        ``find_spec`` raises ``ModuleNotFoundError`` when the parent
        package itself is absent (the Sprint-5 reality), so we
        match the production code's try/except pattern here.
        """
        try:
            spec = importlib.util.find_spec("cognic_agentos.sandbox.runtime")
        except ModuleNotFoundError:
            spec = None
        assert spec is None, (
            "cognic_agentos.sandbox.runtime exists — Sprint 8 has landed. "
            "Update T8's sandbox-availability check to use the real "
            "readiness probe instead of a bare find_spec, and update this "
            "Sprint-5 invariant test to be skipped or removed."
        )


class TestSandboxNotAvailableErrorContract:
    """The ``SandboxNotAvailableError`` message must guide the
    operator to the exact configuration knob that recovers."""

    def test_error_message_cites_adrs_and_recovery(self) -> None:
        from cognic_agentos.core.config import SandboxNotAvailableError

        with pytest.raises(SandboxNotAvailableError) as exc:
            build_settings_without_env_file().model_copy(
                update={"runtime_profile": "prod", "mcp_stdio_enabled": True}
            ).model_post_init(None)

        message = str(exc.value)
        assert "ADR-002" in message, f"ADR-002 missing: {message!r}"
        assert "ADR-004" in message, f"ADR-004 missing: {message!r}"
        assert "Sprint 8" in message, f"Sprint 8 hand-off missing: {message!r}"
        # Operator-actionable recovery hint
        assert "COGNIC_MCP_STDIO_ENABLED" in message or "mcp_stdio_enabled" in message, (
            f"recovery hint missing: {message!r}"
        )

    def test_error_class_inherits_from_runtime_error(self) -> None:
        """``SandboxNotAvailableError`` is a startup-time misconfiguration
        signal — same class hierarchy as :class:`MCPNotAvailableError`
        (also a ``RuntimeError`` subclass per protocol/__init__.py).
        Catching ``RuntimeError`` at the operator-tooling boundary
        catches both."""
        from cognic_agentos.core.config import SandboxNotAvailableError

        assert issubclass(SandboxNotAvailableError, RuntimeError)
