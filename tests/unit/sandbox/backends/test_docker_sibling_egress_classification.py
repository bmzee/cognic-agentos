"""Sprint 8A T10c — egress integration unit tests (NON-env-gated).

Mocked aiodocker; pins:
* proxy_log JSONL readback shape (parses sidecar's access.jsonl into
  ProxyAccessRecord tuples)
* egress-refusal classification: refused records → emit
  sandbox.policy.violated + raise SandboxPolicyViolated with the
  matching closed-enum reason per spec §10.4
* sandbox.lifecycle.exec_completed emission on green path (carries
  {exit_code, proxy_log} payload per spec §4.3)
* dual-homed sidecar attached to BOTH internal + egress networks
* port wire-contract: proxy listens on 3128 per spec §10.2

The env-gated test_docker_sibling_egress.py exercises the same
paths against a real Docker daemon + the canonical proxy image.
These unit tests cover the AgentOS-side logic.

Per spec §10.4 + round-3 P2 invariant + the canonical-artifact
doctrine: the production proxy image is canonical; OSS substitutes
allowed only as clearly-named dev fixtures behind explicit env
flag (deferred to Sprint 14).
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import (
    KernelDefaultCredentialAdapter,
    PackAdmissionContext,
    ProxyAccessRecord,
    SandboxPolicy,
    SandboxPolicyViolated,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    _PROXY_PORT,
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
    _egress_network_name,
    _parse_proxy_log_jsonl,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org",),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)
_ACTOR = Actor(
    subject="consumer-actor-id",
    tenant_id="t-1",
    scopes=frozenset(),
    actor_type="human",
)


# ---------------------------------------------------------------------------
# Port wire-contract (spec §10.2)
# ---------------------------------------------------------------------------


class TestProxyPortWireContract:
    """Spec §10.2 + §7 line 490 — proxy listens on port 3128 on both
    networks. The canonical proxy image's Dockerfile EXPOSEs this port;
    sandbox HTTP_PROXY / HTTPS_PROXY env vars include this port.
    Drift here breaks the wire-contract between AgentOS + the
    canonical proxy image."""

    def test_proxy_port_is_3128_per_spec(self) -> None:
        assert _PROXY_PORT == 3128, (
            "Spec §10.2 + §7 line 490 lock the proxy port at 3128 "
            "(tinyproxy/squid default + the canonical proxy image's "
            "EXPOSEd port). Drift breaks the HTTP_PROXY env contract."
        )

    def test_sandbox_env_includes_3128_port(self) -> None:
        """The sandbox HTTP_PROXY env URL MUST include port 3128.
        A NAT/forwarding change would break the canonical proxy
        image's wire contract."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _sandbox_container_env,
        )

        env = _sandbox_container_env(policy=_POLICY, session_id="abcd" * 8)
        assert env["HTTP_PROXY"] == "http://egress-proxy:3128"
        assert env["HTTPS_PROXY"] == "http://egress-proxy:3128"


# ---------------------------------------------------------------------------
# Egress network naming (spec §10.1 dual-bridge topology)
# ---------------------------------------------------------------------------


class TestEgressNetworkNaming:
    """Per spec §10.1 — each session gets BOTH:
    * internal network (Internal=true; no external gateway)
    * egress network (external gateway; sidecar attached to both)

    Names must be per-session + deterministic + distinguishable from
    the internal network name."""

    def test_egress_network_name_carries_session_prefix(self) -> None:
        session_id = "abcd1234efgh5678ijkl9012mnop3456"
        name = _egress_network_name(session_id)
        assert name.startswith(f"cognic-sb-egress-{session_id[:8]}")

    def test_egress_and_internal_names_are_distinct(self) -> None:
        """Same session_id → different names for internal vs egress
        networks. A collision would have docker treating them as the
        same network → topology break."""
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _internal_network_name,
        )

        session_id = "deadbeef" * 4
        assert _internal_network_name(session_id) != _egress_network_name(session_id)


# ---------------------------------------------------------------------------
# proxy_log JSONL parser (sidecar wire format)
# ---------------------------------------------------------------------------


class TestParseProxyLogJsonl:
    """Wire-contract between the canonical proxy image's access log
    + AgentOS's proxy_log materialiser. Each JSONL line is one
    request audit record."""

    def test_parses_allowed_record(self) -> None:
        line = json.dumps(
            {
                "host": "httpbin.org",
                "method": "GET",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "session-abc",
                "outcome": "allowed",
                "refusal_reason": None,
            }
        )
        records = _parse_proxy_log_jsonl(line)
        assert len(records) == 1
        rec = records[0]
        assert isinstance(rec, ProxyAccessRecord)
        assert rec.host == "httpbin.org"
        assert rec.method == "GET"
        assert rec.outcome == "allowed"
        assert rec.refusal_reason is None

    def test_parses_refused_record_with_reason(self) -> None:
        line = json.dumps(
            {
                "host": "evil.example.com",
                "method": "CONNECT",
                "timestamp": "2026-05-17T12:00:01+00:00",
                "policy_id": "session-abc",
                "outcome": "refused",
                "refusal_reason": "not_in_allow_list",
            }
        )
        records = _parse_proxy_log_jsonl(line)
        assert records[0].outcome == "refused"
        assert records[0].refusal_reason == "not_in_allow_list"

    def test_parses_multiple_jsonl_lines(self) -> None:
        lines = "\n".join(
            [
                json.dumps(
                    {
                        "host": "httpbin.org",
                        "method": "GET",
                        "timestamp": "2026-05-17T12:00:00+00:00",
                        "policy_id": "s",
                        "outcome": "allowed",
                        "refusal_reason": None,
                    }
                ),
                json.dumps(
                    {
                        "host": "api.example.com",
                        "method": "POST",
                        "timestamp": "2026-05-17T12:00:01+00:00",
                        "policy_id": "s",
                        "outcome": "allowed",
                        "refusal_reason": None,
                    }
                ),
            ]
        )
        records = _parse_proxy_log_jsonl(lines)
        assert len(records) == 2

    def test_empty_input_returns_empty_tuple(self) -> None:
        assert _parse_proxy_log_jsonl("") == ()
        assert _parse_proxy_log_jsonl("\n\n") == ()

    def test_skips_blank_lines(self) -> None:
        lines = (
            "\n"
            + json.dumps(
                {
                    "host": "httpbin.org",
                    "method": "GET",
                    "timestamp": "2026-05-17T12:00:00+00:00",
                    "policy_id": "s",
                    "outcome": "allowed",
                    "refusal_reason": None,
                }
            )
            + "\n\n"
        )
        records = _parse_proxy_log_jsonl(lines)
        assert len(records) == 1

    def test_malformed_line_is_skipped_not_crash(self) -> None:
        """A single malformed line MUST NOT crash the parser —
        best-effort: skip the bad line, keep the valid ones. The
        canonical proxy image is well-behaved, but defence-in-depth:
        if a future proxy version emits a partial line during a
        crash, AgentOS should still surface the valid records."""
        lines = "this is not json\n" + json.dumps(
            {
                "host": "httpbin.org",
                "method": "GET",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "s",
                "outcome": "allowed",
                "refusal_reason": None,
            }
        )
        records = _parse_proxy_log_jsonl(lines)
        assert len(records) == 1
        assert records[0].host == "httpbin.org"


# ---------------------------------------------------------------------------
# Backend exec — proxy_log materialisation + audit emission
# ---------------------------------------------------------------------------


def _make_backend_with_proxy_log(
    *,
    proxy_log_jsonl: str = "",
    stdout: bytes = b"",
    exit_code: int = 0,
    oom_killed: bool = False,
) -> tuple[DockerSiblingSandboxBackend, MagicMock]:
    """Build a backend whose mocked sidecar returns the given
    proxy_log JSONL when the backend execs into it to cat the log."""
    import aiodocker
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.core.audit import AuditStore

    docker = MagicMock()
    docker.networks.create = AsyncMock()
    docker.containers.create_or_replace = AsyncMock()
    docker.containers.create_or_replace.return_value.start = AsyncMock()
    docker.networks.get = AsyncMock(side_effect=aiodocker.exceptions.DockerError(404, "not found"))

    # Sandbox container (the one exec runs against)
    kill_event = asyncio.Event()
    mock_container = MagicMock()

    async def _kill(signal: str = "SIGKILL") -> None:
        kill_event.set()

    mock_container.kill = AsyncMock(side_effect=_kill)
    mock_container.stop = AsyncMock()
    mock_container.delete = AsyncMock()
    mock_container.show = AsyncMock(
        return_value={"State": {"OOMKilled": oom_killed, "ExitCode": exit_code}}
    )
    mock_container.stats = AsyncMock(return_value={"cpu_stats": {"cpu_usage": {"total_usage": 0}}})

    # Sandbox exec stream
    messages: list[object] = []
    if stdout:
        messages.append(MagicMock(stream=1, data=stdout))
    message_iter = iter(messages)

    async def _read_out() -> object | None:
        try:
            return next(message_iter)
        except StopIteration:
            return None

    mock_stream = MagicMock()
    mock_stream.read_out = _read_out
    mock_stream.__aenter__ = AsyncMock(return_value=mock_stream)
    mock_stream.__aexit__ = AsyncMock(return_value=None)

    mock_exec_obj = MagicMock()
    mock_exec_obj.start = MagicMock(return_value=mock_stream)
    mock_exec_obj.inspect = AsyncMock(return_value={"ExitCode": exit_code})
    mock_container.exec = AsyncMock(return_value=mock_exec_obj)

    # Sidecar container (for the proxy_log readback exec)
    sidecar_log_messages: list[object] = []
    if proxy_log_jsonl:
        sidecar_log_messages.append(MagicMock(stream=1, data=proxy_log_jsonl.encode()))
    sidecar_iter = iter(sidecar_log_messages)

    async def _sidecar_read_out() -> object | None:
        try:
            return next(sidecar_iter)
        except StopIteration:
            return None

    sidecar_stream = MagicMock()
    sidecar_stream.read_out = _sidecar_read_out
    sidecar_stream.__aenter__ = AsyncMock(return_value=sidecar_stream)
    sidecar_stream.__aexit__ = AsyncMock(return_value=None)

    sidecar_exec_obj = MagicMock()
    sidecar_exec_obj.start = MagicMock(return_value=sidecar_stream)
    sidecar_exec_obj.inspect = AsyncMock(return_value={"ExitCode": 0})

    sidecar_container = MagicMock()
    sidecar_container.exec = AsyncMock(return_value=sidecar_exec_obj)

    async def _get_container(name: str) -> object:
        if name.endswith("-proxy"):
            return sidecar_container
        return mock_container

    docker.containers.get = AsyncMock(side_effect=_get_container)

    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    decision = MagicMock()
    decision.allow = True
    decision.reasoning = ""
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    backend = DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=AuditStore(engine=engine),
        decision_history_store=AsyncMock(),
        settings=settings,
        warm_pool=None,
    )
    return backend, mock_container


def _make_session(
    backend: DockerSiblingSandboxBackend,
) -> DockerSiblingSession:
    return DockerSiblingSession(
        session_id="abcdabcdabcdabcdabcdabcdabcdabcd",
        policy=_POLICY,
        tenant_id="t-1",
        pack_context=_PACK_CTX,
        created_at=datetime.now(UTC),
        warm_pool_hit=False,
        _backend=backend,
        _internal_network_name="cognic-sb-internal-abcdabcd-test",
        _sidecar_container_name="abcdabcdabcdabcdabcdabcdabcdabcd-proxy",
        _actor_subject=_ACTOR.subject,
    )


class TestProxyLogMaterialisedIntoSandboxExecResult:
    """T10c — backend reads the proxy log from the sidecar AFTER
    exec completes + parses it into the SandboxExecResult.proxy_log
    tuple per spec §10.3."""

    @pytest.mark.asyncio
    async def test_green_exec_returns_proxy_log_in_result(self) -> None:
        proxy_log = json.dumps(
            {
                "host": "httpbin.org",
                "method": "GET",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "session-abcd",
                "outcome": "allowed",
                "refusal_reason": None,
            }
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"done",
            exit_code=0,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["curl", "httpbin.org"])
        assert result.exit_code == 0
        assert len(result.proxy_log) == 1
        assert result.proxy_log[0].host == "httpbin.org"
        assert result.proxy_log[0].outcome == "allowed"

    @pytest.mark.asyncio
    async def test_green_exec_with_empty_proxy_log(self) -> None:
        """Sandbox that made no outbound calls → empty proxy_log
        tuple. No SandboxPolicyViolated raised."""
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl="",
            stdout=b"done",
            exit_code=0,
        )
        session = _make_session(backend)

        result = await backend.exec(session, ["echo", "hello"])
        assert result.exit_code == 0
        assert result.proxy_log == ()


class TestEgressRefusalRaisesSandboxPolicyViolated:
    """Per spec §7 line 501 + §10.4 — egress refusals surfaced in
    proxy_log MUST raise SandboxPolicyViolated with the matching
    closed-enum reason (egress_host_not_allow_listed for
    not_in_allow_list refusals; egress_protocol_not_http for
    non_http_connect_target refusals)."""

    @pytest.mark.asyncio
    async def test_not_in_allow_list_refusal_raises_egress_host_not_allow_listed(
        self,
    ) -> None:
        proxy_log = json.dumps(
            {
                "host": "evil.example.com",
                "method": "GET",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "session-abcd",
                "outcome": "refused",
                "refusal_reason": "not_in_allow_list",
            }
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"",
            exit_code=22,  # curl exit code for HTTP error
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["curl", "https://evil.example.com"])
        assert exc.value.reason == "egress_host_not_allow_listed"

    @pytest.mark.asyncio
    async def test_non_http_connect_refusal_raises_egress_protocol_not_http(
        self,
    ) -> None:
        proxy_log = json.dumps(
            {
                "host": "evil.example.com:6379",
                "method": "CONNECT",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "session-abcd",
                "outcome": "refused",
                "refusal_reason": "non_http_connect_target",
            }
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"",
            exit_code=22,
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["curl", "https://evil.example.com:6379"])
        assert exc.value.reason == "egress_protocol_not_http"

    @pytest.mark.asyncio
    async def test_first_refusal_takes_precedence_in_multi_refusal_log(
        self,
    ) -> None:
        """Multiple refusals in the same exec → raise on the FIRST one
        per chronological order. The chain row's proxy_log carries
        all of them; the violation reason matches the first."""
        proxy_log = "\n".join(
            [
                json.dumps(
                    {
                        "host": "first.example.com",
                        "method": "GET",
                        "timestamp": "2026-05-17T12:00:00+00:00",
                        "policy_id": "s",
                        "outcome": "refused",
                        "refusal_reason": "not_in_allow_list",
                    }
                ),
                json.dumps(
                    {
                        "host": "second.example.com:9999",
                        "method": "CONNECT",
                        "timestamp": "2026-05-17T12:00:01+00:00",
                        "policy_id": "s",
                        "outcome": "refused",
                        "refusal_reason": "non_http_connect_target",
                    }
                ),
            ]
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"",
            exit_code=22,
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["curl"])
        # First refusal was not_in_allow_list → egress_host_not_allow_listed
        assert exc.value.reason == "egress_host_not_allow_listed"


class TestExecCompletedAuditEmission:
    """Per spec §4.3 + §7 line 502 — green-path exec emits
    sandbox.lifecycle.exec_completed with payload {exit_code,
    proxy_log}. Cap-violation paths emit sandbox.policy.violated
    instead (no exec_completed for the same exec)."""

    @pytest.mark.asyncio
    async def test_green_exec_emits_lifecycle_exec_completed(self) -> None:
        proxy_log = json.dumps(
            {
                "host": "httpbin.org",
                "method": "GET",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "session-abcd",
                "outcome": "allowed",
                "refusal_reason": None,
            }
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"done",
            exit_code=0,
        )
        session = _make_session(backend)

        await backend.exec(session, ["curl", "httpbin.org"])

        cast(AsyncMock, backend._dh.append_with_precondition).assert_awaited_once()
        await_args = cast(AsyncMock, backend._dh.append_with_precondition).await_args
        assert await_args is not None
        record_builder = await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.lifecycle.exec_completed"
        assert record.payload["exit_code"] == 0
        assert record.payload["session_id"] == session.session_id
        # proxy_log carried on the chain row payload
        assert "proxy_log" in record.payload
        assert len(record.payload["proxy_log"]) == 1
        assert record.iso_controls == ("ISO42001.A.6.2.5",)

    @pytest.mark.asyncio
    async def test_egress_refusal_emits_policy_violated_NOT_exec_completed(
        self,
    ) -> None:
        """When egress refusal raises, ONLY sandbox.policy.violated is
        emitted (NOT exec_completed) — the exec didn't complete
        successfully per spec §7 line 502."""
        proxy_log = json.dumps(
            {
                "host": "evil.example.com",
                "method": "GET",
                "timestamp": "2026-05-17T12:00:00+00:00",
                "policy_id": "session-abcd",
                "outcome": "refused",
                "refusal_reason": "not_in_allow_list",
            }
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"",
            exit_code=22,
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated):
            await backend.exec(session, ["curl"])

        # Exactly ONE chain row — the policy.violated; NOT exec_completed
        cast(AsyncMock, backend._dh.append_with_precondition).assert_awaited_once()
        await_args = cast(AsyncMock, backend._dh.append_with_precondition).await_args
        assert await_args is not None
        record_builder = await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.policy.violated"
        assert record.payload["reason"] == "egress_host_not_allow_listed"


# ---------------------------------------------------------------------------
# R1 P1.1 — proxy sidecar image goes through catalog cosign+SBOM
# ---------------------------------------------------------------------------


class TestProxyImageGoesThroughCatalogVerification:
    """R1 P1.1 reviewer fix — the proxy sidecar IS the egress
    enforcement component. Without canonical-set membership +
    cosign + SBOM verification, a compromised registry could land
    an unverified proxy as a trusted enforcement point. T10c wires
    catalog verification on the proxy image before sidecar start;
    this test pins that ``_start_proxy_sidecar`` calls the catalog's
    verify methods on the proxy image's digest."""

    @pytest.mark.asyncio
    async def test_proxy_image_verified_through_real_canonical_catalog(
        self,
        tmp_path: Path,
    ) -> None:
        """R2 P1 reviewer fix — uses the REAL ``CanonicalImageCatalog``
        (not a mock) so the digest-axis-vs-full-ref bug class can't
        recur. T10c R1's initial fix passed the full OCI ref to
        ``catalog.is_canonical`` / ``verify_cosign_or_refuse`` /
        ``verify_sbom_policy_or_refuse``, but the catalog is
        digest-keyed (catalog.py:279) and refused every session at
        runtime. R2 P1 extracts the digest via rsplit("@", 1) like
        T5 admission does.

        Using the real catalog here pins the contract — a mock that
        accepts anything wouldn't catch the bug class. The subprocess
        cosign + syft calls are monkeypatched per T10a's existing
        pattern so this stays a non-env-gated unit test."""
        import aiodocker
        from sqlalchemy.ext.asyncio import create_async_engine

        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )
        from cognic_agentos.sandbox.catalog import (
            CanonicalImageCatalog,
            CosignVerifyResult,
            SBOMVerifyResult,
        )

        # Real catalog with both runtime + proxy images in the
        # canonical set. Per spec §9 the canonical-set carries
        # FULL OCI refs; internal digest-map is built lazily by
        # CanonicalImageCatalog.
        runtime_image = "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64
        proxy_image = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64
        trust_root = tmp_path / "cognic-cosign.pub"
        trust_root.write_text("# fixture trust root")
        catalog = CanonicalImageCatalog(
            canonical_refs=frozenset({runtime_image, proxy_image}),
            tenant_trust_roots={"t-1": trust_root},
            tenant_allow_lists={"t-1": frozenset()},
        )

        # Monkeypatch the catalog's cosign + syft subprocess shells
        # so this stays a fast unit test (T6 owns the real subprocess
        # impl tests against published artifacts).
        from unittest.mock import patch

        # Mock docker
        docker = MagicMock()
        docker.networks.create = AsyncMock()
        docker.containers.create_or_replace = AsyncMock()
        docker.containers.create_or_replace.return_value.start = AsyncMock()
        mock_network = MagicMock()
        mock_network.connect = AsyncMock()
        mock_network.delete = AsyncMock()
        docker.networks.get = AsyncMock(return_value=mock_network)
        docker.containers.get = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(404, "not found")
        )

        rego = MagicMock()
        decision = MagicMock()
        decision.allow = True
        decision.reasoning = ""
        rego.evaluate = AsyncMock(return_value=decision)
        settings = MagicMock(
            sandbox_per_tenant_max_cpu=4.0,
            sandbox_per_tenant_max_memory=4096,
            sandbox_per_tenant_max_walltime=300.0,
        )
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        backend = DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=AuditStore(engine=engine),
            decision_history_store=AsyncMock(),
            settings=settings,
            warm_pool=None,
        )

        with (
            patch.object(
                catalog,
                "_run_cosign_verify",
                AsyncMock(return_value=CosignVerifyResult(passed=True)),
            ),
            patch.object(
                catalog,
                "_run_syft_inspect",
                AsyncMock(return_value=SBOMVerifyResult(passed=True)),
            ),
        ):
            # With the R2 P1 fix in place, this succeeds. With the
            # R1 P1.1 (full-ref) bug, the real catalog's digest-keyed
            # is_canonical would return False for the proxy and
            # SandboxLifecycleRefused would propagate from create().
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )

    @pytest.mark.asyncio
    async def test_proxy_image_not_canonical_refuses_session_create(
        self,
    ) -> None:
        """If proxy image is somehow not in canonical set (catalog
        misconfig / supply-chain attack), session creation MUST
        refuse with sandbox_image_digest_not_in_canonical_catalog."""
        import aiodocker
        from sqlalchemy.ext.asyncio import create_async_engine

        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.sandbox import SandboxLifecycleRefused
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
        )

        catalog = MagicMock()

        def _is_canonical(ref: str) -> bool:
            # Runtime image canonical; proxy NOT canonical (simulated
            # catalog misconfig).
            return ref == _POLICY.runtime_image

        catalog.is_canonical.side_effect = _is_canonical
        catalog.is_tenant_allow_listed.return_value = False
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)

        docker = MagicMock()
        docker.networks.create = AsyncMock()
        docker.containers.create_or_replace = AsyncMock()
        docker.containers.create_or_replace.return_value.start = AsyncMock()
        mock_network = MagicMock()
        mock_network.connect = AsyncMock()
        mock_network.delete = AsyncMock()
        docker.networks.get = AsyncMock(return_value=mock_network)
        docker.containers.get = AsyncMock(
            side_effect=aiodocker.exceptions.DockerError(404, "not found")
        )

        rego = MagicMock()
        decision = MagicMock()
        decision.allow = True
        decision.reasoning = ""
        rego.evaluate = AsyncMock(return_value=decision)
        settings = MagicMock(
            sandbox_per_tenant_max_cpu=4.0,
            sandbox_per_tenant_max_memory=4096,
            sandbox_per_tenant_max_walltime=300.0,
        )
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        backend = DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=AuditStore(engine=engine),
            decision_history_store=AsyncMock(),
            settings=settings,
            warm_pool=None,
        )

        with pytest.raises(SandboxLifecycleRefused) as exc:
            await backend.create(
                _POLICY,
                actor=_ACTOR,
                tenant_id="t-1",
                pack_context=_PACK_CTX,
                use_warm_pool=False,
            )
        assert exc.value.reason == "sandbox_image_digest_not_in_canonical_catalog"


# ---------------------------------------------------------------------------
# R1 P1.2 — proxy_log read failure fails-closed with egress_audit_unreadable
# ---------------------------------------------------------------------------


class TestProxyLogReadFailureFailsClosed:
    """R1 P1.2 reviewer fix — earlier ``_read_proxy_log_from_sidecar``
    returned ``()`` on any failure → exec() classified no egress
    refusal → emitted green ``exec_completed`` → cap was unenforced
    + no audit trail. T10c R1 fail-closes: any read failure raises
    ``_ProxyLogReadFailure``; exec catches + emits policy.violated
    with ``egress_audit_unreadable`` + raises SandboxPolicyViolated."""

    @pytest.mark.asyncio
    async def test_sidecar_container_gone_raises_egress_audit_unreadable(
        self,
    ) -> None:
        """When sidecar container is 404 during proxy_log readback
        (crashed mid-exec), exec MUST raise SandboxPolicyViolated
        with closed-enum ``egress_audit_unreadable``."""
        import aiodocker
        from sqlalchemy.ext.asyncio import create_async_engine

        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend,
            DockerSiblingSession,
        )

        # Sandbox container exists (workload completed); sidecar
        # is 404 (crashed during exec).
        sandbox_container = MagicMock()
        sandbox_container.kill = AsyncMock()
        sandbox_container.show = AsyncMock(
            return_value={"State": {"OOMKilled": False, "ExitCode": 0}}
        )
        sandbox_container.stats = AsyncMock(
            return_value={"cpu_stats": {"cpu_usage": {"total_usage": 0}}}
        )

        # Workload exec succeeds
        workload_stream = MagicMock()
        workload_stream.read_out = AsyncMock(return_value=None)
        workload_stream.__aenter__ = AsyncMock(return_value=workload_stream)
        workload_stream.__aexit__ = AsyncMock(return_value=None)
        workload_exec = MagicMock()
        workload_exec.start = MagicMock(return_value=workload_stream)
        workload_exec.inspect = AsyncMock(return_value={"ExitCode": 0})
        sandbox_container.exec = AsyncMock(return_value=workload_exec)

        async def _get_container(name: str) -> object:
            if name.endswith("-proxy"):
                # Sidecar is 404 — gone before proxy_log readback
                raise aiodocker.exceptions.DockerError(404, "not found")
            return sandbox_container

        docker = MagicMock()
        docker.networks.create = AsyncMock()
        docker.containers.create_or_replace = AsyncMock()
        docker.containers.create_or_replace.return_value.start = AsyncMock()
        mock_network = MagicMock()
        mock_network.connect = AsyncMock()
        mock_network.delete = AsyncMock()
        docker.networks.get = AsyncMock(return_value=mock_network)
        docker.containers.get = AsyncMock(side_effect=_get_container)

        catalog = MagicMock()
        catalog.is_canonical.return_value = True
        catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
        catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
        rego = MagicMock()
        decision = MagicMock()
        decision.allow = True
        decision.reasoning = ""
        rego.evaluate = AsyncMock(return_value=decision)
        settings = MagicMock(
            sandbox_per_tenant_max_cpu=4.0,
            sandbox_per_tenant_max_memory=4096,
            sandbox_per_tenant_max_walltime=300.0,
        )
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        backend = DockerSiblingSandboxBackend(
            docker_client=docker,
            image_catalog=catalog,
            credential_adapter=KernelDefaultCredentialAdapter(),
            rego_engine=rego,
            audit_store=AuditStore(engine=engine),
            decision_history_store=AsyncMock(),
            settings=settings,
            warm_pool=None,
        )

        session = DockerSiblingSession(
            session_id="abcdabcdabcdabcdabcdabcdabcdabcd",
            policy=_POLICY,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=backend,
            _internal_network_name="net-int",
            _sidecar_container_name="abcdabcdabcdabcdabcdabcdabcdabcd-proxy",
            _actor_subject=_ACTOR.subject,
            _egress_network_name="net-egress",
        )

        with pytest.raises(SandboxPolicyViolated) as exc:
            await backend.exec(session, ["echo", "done"])
        assert exc.value.reason == "egress_audit_unreadable"

        # Policy.violated chain row emitted with the unreadable reason
        cast(AsyncMock, backend._dh.append_with_precondition).assert_awaited_once()
        await_args = cast(AsyncMock, backend._dh.append_with_precondition).await_args
        assert await_args is not None
        record_builder = await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.policy.violated"
        assert record.payload["reason"] == "egress_audit_unreadable"


# ---------------------------------------------------------------------------
# R1 P1.3 — egress-refusal chain row carries the full proxy_log
# ---------------------------------------------------------------------------


class TestEgressRefusalChainRowCarriesFullProxyLog:
    """R1 P1.3 reviewer fix — earlier egress-refusal path emitted
    only ``{reason}`` on policy.violated, dropping the refused
    ProxyAccessRecord data. Spec §10.3 requires examiners to prove
    refused-vs-allowed FROM THE CHAIN ROW ALONE; T10c R1 includes
    the materialised proxy_log on the violation chain row payload."""

    @pytest.mark.asyncio
    async def test_egress_refusal_includes_proxy_log_on_chain_row(
        self,
    ) -> None:
        proxy_log = "\n".join(
            [
                json.dumps(
                    {
                        "host": "evil.example.com",
                        "method": "GET",
                        "timestamp": "2026-05-17T12:00:00+00:00",
                        "policy_id": "session-abc",
                        "outcome": "refused",
                        "refusal_reason": "not_in_allow_list",
                    }
                ),
                json.dumps(
                    {
                        "host": "also-evil.example.com",
                        "method": "POST",
                        "timestamp": "2026-05-17T12:00:01+00:00",
                        "policy_id": "session-abc",
                        "outcome": "refused",
                        "refusal_reason": "not_in_allow_list",
                    }
                ),
                json.dumps(
                    {
                        "host": "allowed.example.com",
                        "method": "GET",
                        "timestamp": "2026-05-17T11:59:59+00:00",
                        "policy_id": "session-abc",
                        "outcome": "allowed",
                        "refusal_reason": None,
                    }
                ),
            ]
        )
        backend, _ = _make_backend_with_proxy_log(
            proxy_log_jsonl=proxy_log,
            stdout=b"",
            exit_code=22,
        )
        session = _make_session(backend)

        with pytest.raises(SandboxPolicyViolated):
            await backend.exec(session, ["curl"])

        cast(AsyncMock, backend._dh.append_with_precondition).assert_awaited_once()
        await_args = cast(AsyncMock, backend._dh.append_with_precondition).await_args
        assert await_args is not None
        record_builder = await_args.kwargs["record_builder"]
        record = record_builder(None)
        assert record.decision_type == "sandbox.policy.violated"
        assert record.payload["reason"] == "egress_host_not_allow_listed"
        # R1 P1.3 — chain row carries ALL 3 proxy_log records
        # (2 refused + 1 allowed) so examiners have the full
        # outbound-call history.
        assert "proxy_log" in record.payload
        assert len(record.payload["proxy_log"]) == 3, (
            "Egress refusal chain row MUST carry the FULL proxy_log "
            "(all attempted calls, refused + allowed). Spec §10.3. "
            "R1 P1.3 reviewer fix."
        )
        # Verify the records' hosts are present in the payload
        payload_hosts = {rec["host"] for rec in record.payload["proxy_log"]}
        assert payload_hosts == {
            "evil.example.com",
            "also-evil.example.com",
            "allowed.example.com",
        }
