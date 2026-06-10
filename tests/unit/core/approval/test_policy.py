from __future__ import annotations

import json
from typing import Any

import pytest

from cognic_agentos.core.approval.policy import _MINIMAL_SUBPROCESS_ENV, ApprovalPolicy


class _FakeOpa:
    def __init__(self, opa_path: str | None) -> None:
        self._opa_path = opa_path
        self._bundle_path = "/x/tools.rego"
        self._eval_timeout_s = 5.0


def _stub_run(value: str | None) -> Any:
    class _R:
        returncode = 0
        stderr = ""
        stdout = json.dumps(
            {"result": [{"expressions": [{"value": value}]}]}
            if value is not None
            else {"result": []}
        )

    def _run(*a: Any, **k: Any) -> Any:
        return _R()

    return _run


@pytest.mark.asyncio
async def test_classify_maps_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "cognic_agentos.core.approval.policy.subprocess.run",
        _stub_run("require_single_approval"),
    )
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="customer_data_read") == "require_single_approval"


@pytest.mark.asyncio
async def test_classify_unknown_value_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # OPA returns a value outside the 3-value enum -> fail-closed strictest.
    monkeypatch.setattr("cognic_agentos.core.approval.policy.subprocess.run", _stub_run("bogus"))
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="x") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_empty_result_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # No rule matched (empty result set) -> RegoEvaluationError -> fail-closed.
    monkeypatch.setattr("cognic_agentos.core.approval.policy.subprocess.run", _stub_run(None))
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="x") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_opa_unavailable_fails_closed() -> None:
    pol = ApprovalPolicy(opa_engine=_FakeOpa(None))  # no opa path
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_nonzero_exit_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _R:
        returncode = 1
        stderr = "boom"
        stdout = ""

    def _run(*a: Any, **k: Any) -> Any:
        return _R()

    monkeypatch.setattr("cognic_agentos.core.approval.policy.subprocess.run", _run)
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


def _stub_raw_stdout(stdout: str) -> Any:
    class _R:
        returncode = 0
        stderr = ""

    def _run(*a: Any, **k: Any) -> Any:
        r = _R()
        r.stdout = stdout  # type: ignore[attr-defined]
        return r

    return _run


@pytest.mark.asyncio
async def test_classify_malformed_json_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "cognic_agentos.core.approval.policy.subprocess.run", _stub_raw_stdout("not json")
    )
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_bad_result_shape_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "cognic_agentos.core.approval.policy.subprocess.run",
        _stub_raw_stdout(json.dumps({"result": [{"no_expressions": True}]})),
    )
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_non_string_value_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cognic_agentos.core.approval.policy.subprocess.run", _stub_run(None))
    # Override with an int value (not a string).
    monkeypatch.setattr(
        "cognic_agentos.core.approval.policy.subprocess.run",
        _stub_raw_stdout(json.dumps({"result": [{"expressions": [{"value": 123}]}]})),
    )
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_timeout_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess as _sp

    def _run(*a: Any, **k: Any) -> Any:
        raise _sp.TimeoutExpired(cmd="opa", timeout=5.0)

    monkeypatch.setattr("cognic_agentos.core.approval.policy.subprocess.run", _run)
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


@pytest.mark.asyncio
async def test_classify_binary_missing_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _run(*a: Any, **k: Any) -> Any:
        raise FileNotFoundError("opa gone")

    monkeypatch.setattr("cognic_agentos.core.approval.policy.subprocess.run", _run)
    pol = ApprovalPolicy(opa_engine=_FakeOpa("/usr/bin/opa"))
    assert await pol.classify(risk_tier="payment_action") == "require_4_eyes"


def test_subprocess_env_parity() -> None:
    # Drift detector vs OPAEngine's minimal env (test-only import of both;
    # no runtime cross-import, per the drift-detector doctrine).
    from cognic_agentos.core.policy.engine import _MINIMAL_SUBPROCESS_ENV as engine_env

    assert engine_env == _MINIMAL_SUBPROCESS_ENV
