"""Sprint 4 T2 — OPAEngine load-from-disk + Decision shape contract.

Critical-controls module per AGENTS.md (``core/policy/engine.py`` —
admission-control substrate; per-file gate ≥95% line / ≥90% branch
once T15 extends ``tools/check_critical_coverage.py``).

Tests cover:
- Engine construction (sync ``__init__``) loads the bundle, computes
  its sha256, refuses on missing or syntactically-invalid bundle.
- Async ``OPAEngine.create()`` factory: same construction + emits
  ``policy.bundle_loaded`` into ``decision_history`` after
  construction succeeds.
- ``Decision`` dataclass shape (frozen, slotted, ``decision_data``
  slot present per Q8 lock).
- ``evaluate()`` shells out via secure subprocess (list-form argv,
  shell=False, explicit minimal env, strict timeout).
- Subprocess failure modes: non-zero exit → RegoEvaluationError;
  malformed JSON → RegoEvaluationError; TimeoutExpired →
  RegoEvaluationError; OPA binary missing → OpaNotInstalledError.
- Audit emissions: ``policy.bundle_loaded`` once at ``create()``;
  ``policy.decision_evaluated`` per ``evaluate()`` call. Payload
  carries ``input_fingerprint`` (sha256 of canonical input) but
  NEVER the input itself.

OPA is not assumed to be installed in the test environment — every
subprocess call is shimmed via ``patch`` per Sprint-4 plan §5
secure-subprocess invariants.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.policy.engine import (
    Decision,
    OPAEngine,
    OpaNotInstalledError,
    RegoBundleInvalidError,
    RegoBundleNotFoundError,
    RegoEvaluationError,
)
from tests.unit.core.policy.conftest import (
    fake_completed_process,
    fake_opa_eval_response,
    opa_shim,
    write_valid_bundle,
)

# ---------------------------------------------------------------------------
# TestOPAEngineConstruction — bundle-load + opa-resolve happy/sad paths.
# ---------------------------------------------------------------------------


class TestOPAEngineConstruction:
    def test_missing_bundle_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        with pytest.raises(RegoBundleNotFoundError, match="bundle not found"):
            OPAEngine(
                bundle_path=tmp_path / "missing.rego",
                audit_store=audit_store,
                decision_history_store=decision_history_store,
            )

    def test_invalid_bundle_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """When OPA is available + reports non-zero exit on
        ``opa fmt --diff``, the engine refuses construction."""
        bundle = tmp_path / "bad.rego"
        bundle.write_text("this is not valid rego")
        with patch("cognic_agentos.core.policy.engine.subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["opa", "fmt", "--diff", str(bundle)],
                returncode=1,
                stdout="",
                stderr="rego_parse_error: unexpected ident token at line 1",
            )
            with pytest.raises(RegoBundleInvalidError, match=r"syntax|parse"):
                OPAEngine(
                    bundle_path=bundle,
                    audit_store=audit_store,
                    decision_history_store=decision_history_store,
                    opa_path="/usr/local/bin/opa",
                )

    def test_no_opa_at_construction_skips_syntax_validation(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When OPA is not on PATH at construction time, syntax
        validation is deferred — engine constructs cleanly. This
        means a kernel-only image (no OPA binary) can boot the engine
        + lazily fail at ``evaluate()`` rather than fail at startup."""
        monkeypatch.setattr("cognic_agentos.core.policy.engine.shutil.which", lambda name: None)
        bundle = write_valid_bundle(tmp_path)
        # Construction succeeds — no syntax check possible.
        engine = OPAEngine(
            bundle_path=bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=None,
        )
        # The bundle sha256 was still computed (it's a Python-side hash).
        assert len(engine.bundle_sha256) == 64

    def test_bundle_sha256_is_hex_64(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """SHA-256 hex digest is 64 chars; matches Python's hashlib output."""
        monkeypatch.setattr("cognic_agentos.core.policy.engine.shutil.which", lambda name: None)
        bundle = write_valid_bundle(tmp_path)
        engine = OPAEngine(
            bundle_path=bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=None,
        )
        expected = hashlib.sha256(bundle.read_bytes()).hexdigest()
        assert engine.bundle_sha256 == expected


# ---------------------------------------------------------------------------
# TestAsyncCreateFactory — async classmethod that emits policy.bundle_loaded.
# ---------------------------------------------------------------------------


class TestAsyncCreateFactory:
    async def test_create_emits_policy_bundle_loaded(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``OPAEngine.create()`` is the async factory that combines
        sync construction + async ``policy.bundle_loaded`` emission.
        After ``create()`` returns, exactly one decision_history row
        exists with event_type=policy.bundle_loaded carrying the
        bundle path + sha256 in payload."""
        monkeypatch.setattr("cognic_agentos.core.policy.engine.shutil.which", lambda name: None)
        bundle = write_valid_bundle(tmp_path)
        engine = await OPAEngine.create(
            bundle_path=bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=None,
        )
        async with policy_engine_db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        bundle_loaded_rows = [r for r in rows if r.event_type == "policy.bundle_loaded"]
        assert len(bundle_loaded_rows) == 1, (
            f"expected exactly one policy.bundle_loaded emission; got {len(bundle_loaded_rows)}"
        )
        row = bundle_loaded_rows[0]
        assert row.payload["bundle_sha256"] == engine.bundle_sha256
        assert "bundle_path" in row.payload
        assert "loaded_at" in row.payload
        # Privacy: bundle source content NEVER in the payload.
        assert "input.attestation_grade" not in str(row.payload)


# ---------------------------------------------------------------------------
# TestDecisionShape — frozen+slotted with decision_data slot.
# ---------------------------------------------------------------------------


class TestDecisionShape:
    def test_decision_is_frozen(self) -> None:
        d = Decision(
            allow=True,
            rule_matched="data.cognic.supply_chain.allow",
            reasoning="full grade",
            decision_data={"attestation_grade": "full"},
        )
        assert dataclasses.is_dataclass(Decision)
        with pytest.raises(dataclasses.FrozenInstanceError):
            d.allow = False  # type: ignore[misc]

    def test_decision_data_can_be_none(self) -> None:
        d = Decision(allow=False, rule_matched=None, reasoning="default deny", decision_data=None)
        assert d.decision_data is None

    def test_decision_uses_slots(self) -> None:
        """slots=True means no __dict__; protect against accidental field
        additions at runtime (which would silently bypass the frozen
        guarantee)."""
        d = Decision(allow=True, rule_matched="r", reasoning="x", decision_data=None)
        assert not hasattr(d, "__dict__")


# ---------------------------------------------------------------------------
# TestEvaluate — happy path + emission shape + secure-subprocess invariants.
# ---------------------------------------------------------------------------


class TestEvaluate:
    async def test_full_grade_input_returns_allow_true(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=True)),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            decision = await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )
        assert decision.allow is True
        assert decision.rule_matched == "data.cognic.supply_chain.allow"

    async def test_partial_grade_input_returns_allow_false(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=False)),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            decision = await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "partial"},
            )
        assert decision.allow is False

    async def test_missing_opa_binary_at_evaluate_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When OPA was unavailable at construction (lazy path) AND
        is still unavailable at evaluate() time, fail-closed with
        OpaNotInstalledError. This is the kernel-only-image scenario."""
        monkeypatch.setattr("cognic_agentos.core.policy.engine.shutil.which", lambda name: None)
        bundle = write_valid_bundle(tmp_path)
        engine = await OPAEngine.create(
            bundle_path=bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=None,
        )
        with pytest.raises(OpaNotInstalledError, match="opa not found"):
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )

    async def test_subprocess_argv_is_list_form_no_shell(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Critical: shell=False and argv is a list. Regression-pin
        against accidentally enabling shell=True or building a
        shell-string. Per Sprint-4 plan §2 + §5 invariant 1."""
        bundle = write_valid_bundle(tmp_path)
        captured: dict[str, Any] = {}

        def _capture_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "fmt" in argv:
                return fake_completed_process(stdout="")
            captured["argv"] = list(argv)
            captured["shell"] = kwargs.get("shell")
            captured["env"] = kwargs.get("env")
            captured["timeout"] = kwargs.get("timeout")
            return fake_completed_process(stdout=fake_opa_eval_response(allow=True))

        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=_capture_run,
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )
        assert isinstance(captured["argv"], list), "argv must be list-form"
        assert captured["shell"] is False, "shell=False is mandatory"
        assert captured["argv"][0].endswith("opa"), "first argv element is the opa binary"
        assert captured["argv"][1] == "eval"

    async def test_subprocess_env_is_minimal_no_environ_passthrough(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Per Sprint-4 plan §2 invariant 5: explicit minimal env;
        no os.environ passthrough. The shimmed subprocess receives
        only PATH + (optionally) HOME — never arbitrary env."""
        bundle = write_valid_bundle(tmp_path)
        captured: dict[str, Any] = {}

        def _capture_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "fmt" in argv:
                return fake_completed_process(stdout="")
            captured["env"] = kwargs.get("env")
            return fake_completed_process(stdout=fake_opa_eval_response(allow=True))

        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=_capture_run,
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )
        env = captured["env"]
        assert env is not None, "env must be explicit (not None — that means inherit)"
        assert set(env.keys()) <= {"PATH", "HOME"}, (
            f"env must be minimal (PATH/HOME only); got keys: {set(env.keys())}"
        )

    async def test_subprocess_timeout_passed_through(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Strict timeout per §5 invariant 5. The engine's
        eval_timeout_s ctor arg becomes subprocess.run's timeout
        for the eval call (the syntax-check uses a separate ceiling)."""
        bundle = write_valid_bundle(tmp_path)
        captured: dict[str, Any] = {}

        def _capture_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "fmt" in argv:
                return fake_completed_process(stdout="")
            captured["timeout"] = kwargs.get("timeout")
            return fake_completed_process(stdout=fake_opa_eval_response(allow=True))

        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=_capture_run,
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
                eval_timeout_s=2.5,
            )
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )
        assert captured["timeout"] == 2.5

    async def test_evaluate_emits_policy_decision_evaluated(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        """Per Q7 lock: every evaluate() call emits a
        policy.decision_evaluated row chained into decision_history.
        Payload includes input_fingerprint (sha256(canonical_bytes(input)))
        — NEVER the input itself (input may carry tenant/pack identifiers)."""
        bundle = write_valid_bundle(tmp_path)
        input_data = {"attestation_grade": "full", "tenant_id": "tenant-secret-123"}
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=True)),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input=input_data,
            )
        async with policy_engine_db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        evaluated_rows = [r for r in rows if r.event_type == "policy.decision_evaluated"]
        assert len(evaluated_rows) == 1
        payload = evaluated_rows[0].payload
        assert payload["decision_point"] == "data.cognic.supply_chain.allow"
        # input_fingerprint is sha256 of canonical_bytes(input).
        expected_fp = hashlib.sha256(canonical_bytes(input_data)).hexdigest()
        assert payload["input_fingerprint"] == expected_fp
        # Privacy: tenant_id from input must NOT appear in payload.
        assert "tenant-secret-123" not in str(payload)
        assert "input" not in payload
        # Outcome + bundle binding.
        assert payload["outcome"] in ("allow", "deny")
        assert payload["bundle_sha256"] == engine.bundle_sha256


# ---------------------------------------------------------------------------
# TestEvaluateFailureModes — fail-closed on every subprocess pathology.
# ---------------------------------------------------------------------------


class TestEvaluateFailureModes:
    async def test_non_zero_exit_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout="", eval_returncode=1),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError, match=r"non-zero|exit"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )

    async def test_malformed_json_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout="not valid json"),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError, match=r"parse|JSON|json"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )

    async def test_timeout_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)

        def _run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "fmt" in argv:
                return fake_completed_process(stdout="")
            raise subprocess.TimeoutExpired(cmd=["opa"], timeout=1.0)

        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=_run,
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
                eval_timeout_s=1.0,
            )
            with pytest.raises(RegoEvaluationError, match="timeout"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )

    async def test_empty_result_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """OPA returns ``{"result": []}`` when the query has no matching
        bindings (e.g. typo in decision_point). Treat as fail-closed
        rather than synthesise a deny."""
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=json.dumps({"result": []})),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError, match=r"empty|no result"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )

    async def test_non_boolean_result_fails_closed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """The Sprint-4 seed only handles boolean allow rules. A
        non-boolean expression value (e.g. dict, string) is malformed
        for this evaluator's contract."""
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(
                eval_stdout=json.dumps({"result": [{"expressions": [{"value": "not-a-bool"}]}]})
            ),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError, match=r"boolean|bool"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )


# ---------------------------------------------------------------------------
# TestEvaluateFailureEmissions — R1 reviewer-P2 §1: every fail-closed path
# emits a policy.decision_evaluated row before re-raising.
# ---------------------------------------------------------------------------


class TestEvaluateFailureEmissions:
    """Per R1 reviewer-P2 §1: every ``evaluate()`` call produces an
    admission-control decision. Failures are deny-by-default and MUST
    leave a chained ``policy.decision_evaluated`` row in
    decision_history with ``outcome="deny"`` + ``error_kind`` so an
    examiner can prove the engine was queried even when OPA failed.
    """

    async def _decision_evaluated_rows(self, db: AsyncEngine) -> list[Any]:
        async with db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        return [r for r in rows if r.event_type == "policy.decision_evaluated"]

    async def test_opa_not_installed_at_evaluate_emits_deny(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OPA-missing-at-evaluate (kernel-only-image scenario) emits a
        deny row before raising OpaNotInstalledError."""
        monkeypatch.setattr("cognic_agentos.core.policy.engine.shutil.which", lambda name: None)
        bundle = write_valid_bundle(tmp_path)
        engine = await OPAEngine.create(
            bundle_path=bundle,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=None,
        )
        with pytest.raises(OpaNotInstalledError):
            await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full"},
            )
        rows = await self._decision_evaluated_rows(policy_engine_db)
        assert len(rows) == 1
        payload = rows[0].payload
        assert payload["outcome"] == "deny"
        assert payload["error_kind"] == "opa_not_installed"
        assert payload["bundle_sha256"] == engine.bundle_sha256

    async def test_subprocess_non_zero_exit_emits_deny(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(
                eval_stdout="",
                eval_returncode=2,
                eval_stderr="boom from opa: rego evaluation error",
            ),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        rows = await self._decision_evaluated_rows(policy_engine_db)
        assert len(rows) == 1
        payload = rows[0].payload
        assert payload["outcome"] == "deny"
        assert payload["error_kind"] == "non_zero_exit"
        # R2 reviewer-P2 §1 — privacy: payload carries sanitized stderr
        # fingerprint (not raw stderr, which may contain policy-controlled
        # text). Python-level exception keeps the raw text for debugging.
        assert payload["exit_code"] == 2
        expected_stderr = "boom from opa: rego evaluation error"
        assert (
            payload["stderr_sha256"] == hashlib.sha256(expected_stderr.encode("utf-8")).hexdigest()
        )
        assert payload["stderr_len"] == len(expected_stderr.encode("utf-8"))
        # The raw stderr text MUST NOT appear in the payload.
        assert "boom from opa" not in str(payload)

    async def test_subprocess_timeout_emits_deny(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)

        def _run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "fmt" in argv:
                return fake_completed_process(stdout="")
            raise subprocess.TimeoutExpired(cmd=["opa"], timeout=1.0)

        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=_run,
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
                eval_timeout_s=1.0,
            )
            with pytest.raises(RegoEvaluationError, match="timeout"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        rows = await self._decision_evaluated_rows(policy_engine_db)
        assert len(rows) == 1
        assert rows[0].payload["outcome"] == "deny"
        assert rows[0].payload["error_kind"] == "timeout"

    async def test_malformed_json_emits_deny(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout="not valid json"),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        rows = await self._decision_evaluated_rows(policy_engine_db)
        assert len(rows) == 1
        assert rows[0].payload["outcome"] == "deny"
        assert rows[0].payload["error_kind"] == "parse_failure"

    async def test_empty_result_emits_deny(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=json.dumps({"result": []})),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        rows = await self._decision_evaluated_rows(policy_engine_db)
        assert len(rows) == 1
        assert rows[0].payload["outcome"] == "deny"
        assert rows[0].payload["error_kind"] == "parse_failure"


# ---------------------------------------------------------------------------
# TestPinnedOpaPathMissing — R1 reviewer-P2 §2: invalid pinned opa_path
# stays in the OpaNotInstalledError taxonomy (never leaks raw FileNotFoundError).
# ---------------------------------------------------------------------------


class TestPinnedOpaPathMissing:
    """Per R1 reviewer-P2 §2: when an operator pins ``opa_path`` to a
    binary that doesn't exist on disk, ``subprocess.run`` raises raw
    ``FileNotFoundError``. Catch + re-raise as ``OpaNotInstalledError``
    so callers see one fail-closed exception class for the whole
    "no OPA available" condition.
    """

    def test_construction_with_missing_pinned_opa_path_raises_not_installed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Construction-time syntax check sees FileNotFoundError →
        OpaNotInstalledError (NOT FileNotFoundError leaking through)."""
        bundle = write_valid_bundle(tmp_path)

        def _run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError(2, "No such file or directory", argv[0])

        with (
            patch(
                "cognic_agentos.core.policy.engine.subprocess.run",
                side_effect=_run,
            ),
            pytest.raises(OpaNotInstalledError, match=r"pinned path"),
        ):
            OPAEngine(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/nonexistent/path/to/opa",
            )

    async def test_evaluate_with_missing_pinned_opa_path_raises_not_installed(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        """Evaluate-time path: construction succeeds (syntax-check shim
        returns success) but the binary is removed before evaluate
        actually runs. evaluate's subprocess.run raises FileNotFoundError →
        engine catches + re-raises OpaNotInstalledError + emits a
        deny row to decision_history.
        """
        bundle = write_valid_bundle(tmp_path)

        def _run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if "fmt" in argv:
                # Construction syntax-check: succeed.
                return fake_completed_process(stdout="")
            # Evaluate-time: simulate the binary being gone.
            raise FileNotFoundError(2, "No such file or directory", argv[0])

        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=_run,
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(OpaNotInstalledError, match=r"pinned path"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        async with policy_engine_db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        deny_rows = [
            r
            for r in rows
            if r.event_type == "policy.decision_evaluated"
            and r.payload.get("error_kind") == "opa_not_installed"
        ]
        assert len(deny_rows) == 1
        assert deny_rows[0].payload["outcome"] == "deny"


# ---------------------------------------------------------------------------
# TestFailurePayloadPrivacy — R2 reviewer-P2 §1: raw stderr/stdout MUST NOT
# cross into decision_history. Only sanitized engine-generated fingerprints.
# ---------------------------------------------------------------------------


class TestFailurePayloadPrivacy:
    """R2 reviewer-P2 §1: OPA stderr/stdout are external subprocess
    strings that may contain policy-controlled text, paths, or input-
    derived debug output. Persisting them into ``decision_history``
    breaks the chain's privacy claim that only ``input_fingerprint``
    crosses the boundary. The payload must record only sanitized
    engine-generated fields (sha256/len fingerprints + exit code).
    """

    async def test_tenant_secret_in_stderr_not_persisted_to_chain(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        """Concrete privacy regression: a hostile or careless OPA build
        emits a tenant identifier in stderr (e.g. via ``print(...)`` in
        a custom Rego function). The fingerprint pattern guarantees the
        secret never crosses into the immutable chain."""
        tenant_secret = "tenant-acme-bank-prod-secret-9f2a1c"
        leaky_stderr = (
            f"opa eval crashed at file:///etc/cognic/data.json: "
            f"context contained tenant_id={tenant_secret} during eval"
        )
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(
                eval_stdout="",
                eval_returncode=1,
                eval_stderr=leaky_stderr,
            ),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        # The chained row exists.
        async with policy_engine_db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        deny_rows = [
            r
            for r in rows
            if r.event_type == "policy.decision_evaluated"
            and r.payload.get("error_kind") == "non_zero_exit"
        ]
        assert len(deny_rows) == 1
        payload = deny_rows[0].payload
        # Privacy contract: tenant secret MUST NOT appear anywhere in
        # the persisted payload (top-level OR nested string-coerced).
        assert tenant_secret not in str(payload), (
            f"tenant secret leaked into decision_history payload: {payload!r}"
        )
        # File-path leak prevention: the /etc/cognic/data.json string
        # also must not appear.
        assert "/etc/cognic/data.json" not in str(payload)
        # The sanitized fingerprints DO appear and match.
        expected_sha = hashlib.sha256(leaky_stderr.encode("utf-8")).hexdigest()
        assert payload["stderr_sha256"] == expected_sha
        assert payload["stderr_len"] == len(leaky_stderr.encode("utf-8"))

    async def test_parse_failure_persists_only_stdout_fingerprint_not_content(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
    ) -> None:
        """Same privacy contract for parse-failure path: stdout (the
        malformed JSON OPA returned) MUST NOT cross into the chain."""
        # Construct a stdout payload containing a sentinel string that
        # the test asserts does not leak.
        sentinel = "MUST-NOT-LEAK-PAYLOAD-SENTINEL"
        leaky_stdout = f'{{"result": [{{"expressions": [{{"value": "{sentinel}"}}]}}]}}'
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=leaky_stdout),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        async with policy_engine_db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        deny_rows = [
            r
            for r in rows
            if r.event_type == "policy.decision_evaluated"
            and r.payload.get("error_kind") == "parse_failure"
        ]
        assert len(deny_rows) == 1
        payload = deny_rows[0].payload
        # The sentinel must NOT appear.
        assert sentinel not in str(payload), (
            f"stdout content leaked into decision_history payload: {payload!r}"
        )
        # The sanitized fingerprint matches.
        expected_sha = hashlib.sha256(leaky_stdout.encode("utf-8")).hexdigest()
        assert payload["stdout_sha256"] == expected_sha
        assert payload["stdout_len"] == len(leaky_stdout.encode("utf-8"))


# ---------------------------------------------------------------------------
# TestEvalTimeoutValidation — R2 reviewer-P2 §2: OPAEngine is a directly-
# constructable critical-control primitive; validate eval_timeout_s > 0
# at the engine boundary, not just in Settings.
# ---------------------------------------------------------------------------


class TestEvalTimeoutValidation:
    def test_zero_eval_timeout_rejected(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with pytest.raises(ValueError, match=r"eval_timeout_s.*finite.*> 0"):
            OPAEngine(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path=None,
                eval_timeout_s=0,
            )

    def test_negative_eval_timeout_rejected(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        bundle = write_valid_bundle(tmp_path)
        with pytest.raises(ValueError, match=r"eval_timeout_s.*finite.*> 0"):
            OPAEngine(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path=None,
                eval_timeout_s=-0.5,
            )


# ---------------------------------------------------------------------------
# TestNonObjectJSONRoot — R3 reviewer-P2 §1: non-object OPA JSON output
# (list / string / number) MUST fail-closed via the documented taxonomy +
# emit the deny evidence row, not leak a raw AttributeError.
# ---------------------------------------------------------------------------


class TestNonObjectJSONRoot:
    """R3 reviewer-P2 §1: ``json.loads`` returns whatever JSON value the
    input encodes — list, string, number, bool, null, or object. The
    Sprint-4 seed only handles object-shaped responses; any other
    shape MUST surface as ``RegoEvaluationError`` (with a chained
    deny evidence row) rather than a raw ``AttributeError`` from
    ``payload.get("result", [])``.
    """

    @pytest.mark.parametrize(
        ("non_object_stdout", "label"),
        [
            ("[]", "empty_list"),
            ('["unexpected"]', "list_root"),
            ('"ok"', "string_root"),
            ("42", "number_root"),
            ("true", "bool_root"),
            ("null", "null_root"),
        ],
    )
    async def test_non_object_root_fails_closed_with_evidence(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        policy_engine_db: AsyncEngine,
        non_object_stdout: str,
        label: str,
    ) -> None:
        """Each non-object JSON shape raises ``RegoEvaluationError``
        AND emits exactly one ``policy.decision_evaluated`` deny row
        with ``error_kind="parse_failure"``."""
        bundle = write_valid_bundle(tmp_path)
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=non_object_stdout),
        ):
            engine = await OPAEngine.create(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            with pytest.raises(RegoEvaluationError, match=r"object"):
                await engine.evaluate(
                    decision_point="data.cognic.supply_chain.allow",
                    input={"attestation_grade": "full"},
                )
        async with policy_engine_db.connect() as conn:
            rows = list((await conn.execute(select(_decision_history))).fetchall())
        deny_rows = [
            r
            for r in rows
            if r.event_type == "policy.decision_evaluated"
            and r.payload.get("error_kind") == "parse_failure"
        ]
        assert len(deny_rows) == 1, (
            f"expected exactly one parse_failure deny row for {label}; got {len(deny_rows)}"
        )
        payload = deny_rows[0].payload
        assert payload["outcome"] == "deny"
        # stdout fingerprint matches what we passed in (privacy contract).
        expected_sha = hashlib.sha256(non_object_stdout.encode("utf-8")).hexdigest()
        assert payload["stdout_sha256"] == expected_sha


# ---------------------------------------------------------------------------
# TestNonFiniteEvalTimeout — R3 reviewer-P2 §2: NaN / infinity must be
# rejected at __init__ because subprocess.run treats them as effectively
# unbounded, defeating the §5 strict-timeout invariant.
# ---------------------------------------------------------------------------


class TestNonFiniteEvalTimeout:
    @pytest.mark.parametrize(
        "bad_timeout",
        [
            float("nan"),
            float("inf"),
            float("-inf"),
        ],
    )
    def test_non_finite_eval_timeout_rejected(
        self,
        tmp_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        bad_timeout: float,
    ) -> None:
        """NaN comparisons evaluate to False, so a bare ``<= 0`` guard
        passes NaN. Infinity is unbounded. Both disable the strict
        timeout invariant. The ``math.isfinite`` check rejects them
        explicitly."""
        bundle = write_valid_bundle(tmp_path)
        with pytest.raises(ValueError, match=r"finite"):
            OPAEngine(
                bundle_path=bundle,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path=None,
                eval_timeout_s=bad_timeout,
            )


# ---------------------------------------------------------------------------
# TestDefaultSupplyChainBundle — Sprint 4 T3.
#
# Verifies the engine integrates with the actual policies/_default/
# supply_chain.rego bundle file: file present, sha256 deterministically
# computed, syntax-check passes (shimmed), evaluate() returns the
# expected Decision shape per scenario.
#
# IMPORTANT: these are SHIM-based tests — the real Rego logic
# (allow rules, default-deny, partial-grade gating) is exercised by
# T13's @pytest.mark.opa_real env-gated integration arm against the
# Dockerfile-pinned OPA binary. Sprint-4 unit tests only verify the
# engine + bundle-file glue, not the Rego semantics.
# ---------------------------------------------------------------------------


_REAL_BUNDLE = Path(__file__).parents[4] / "policies" / "_default" / "supply_chain.rego"
_REAL_ALLOWLIST = Path(__file__).parents[4] / "policies" / "_default" / "plugin_allowlist.json"


class TestDefaultSupplyChainBundle:
    def test_real_bundle_file_exists(self) -> None:
        """Locked at the documented path — Sprint-4 plan T3 + ADR-015 §
        "Sprint 4 (seed)"."""
        assert _REAL_BUNDLE.is_file(), f"default supply-chain bundle missing at {_REAL_BUNDLE}"

    def test_real_bundle_content_stability(self) -> None:
        """Pin the load-bearing rules so a refactor that drops the
        default-deny posture or the grace-period clause is caught
        even without OPA in the unit-test environment. Sprint-4 plan
        §3 mandates these specific clauses."""
        text = _REAL_BUNDLE.read_text()
        assert "package cognic.supply_chain" in text
        assert "default allow" in text
        # Two allow paths: full-grade always; partial-grade unless
        # tenant requires full.
        assert 'input.attestation_grade == "full"' in text
        assert 'input.attestation_grade == "partial"' in text
        assert "not input.tenant_policy.require_full" in text

    async def test_engine_constructs_against_real_bundle(
        self,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """End-to-end: engine reads the real bundle file, computes
        sha256, runs shimmed `opa fmt --diff` (success), emits
        `policy.bundle_loaded`. Confirms the bundle is parseable as
        a Path + the engine doesn't choke on the actual file content."""
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=True)),
        ):
            engine = await OPAEngine.create(
                bundle_path=_REAL_BUNDLE,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
        # Real-file sha256 is deterministic + matches a fresh hash of
        # the same bytes.
        expected_sha = hashlib.sha256(_REAL_BUNDLE.read_bytes()).hexdigest()
        assert engine.bundle_sha256 == expected_sha

    async def test_full_grade_input_allows_through_real_bundle(
        self,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Mirrors Sprint-4 plan T3 Step 1 scenario A. Shim returns
        allow=True for the full-grade input shape; engine surfaces a
        Decision(allow=True). Real Rego-rule correctness is tested in
        T13's env-gated arm."""
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=True)),
        ):
            engine = await OPAEngine.create(
                bundle_path=_REAL_BUNDLE,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            decision = await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={"attestation_grade": "full", "tenant_policy": {}},
            )
        assert decision.allow is True
        assert decision.rule_matched == "data.cognic.supply_chain.allow"

    async def test_partial_grade_input_with_lenient_tenant_allows(
        self,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Mirrors Sprint-4 plan T3 Step 1 scenario B."""
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=True)),
        ):
            engine = await OPAEngine.create(
                bundle_path=_REAL_BUNDLE,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            decision = await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={
                    "attestation_grade": "partial",
                    "tenant_policy": {"require_full": False},
                },
            )
        assert decision.allow is True

    async def test_partial_grade_input_with_strict_tenant_denies(
        self,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        """Mirrors Sprint-4 plan T3 Step 1 scenario C."""
        with patch(
            "cognic_agentos.core.policy.engine.subprocess.run",
            side_effect=opa_shim(eval_stdout=fake_opa_eval_response(allow=False)),
        ):
            engine = await OPAEngine.create(
                bundle_path=_REAL_BUNDLE,
                audit_store=audit_store,
                decision_history_store=decision_history_store,
                opa_path="/usr/local/bin/opa",
            )
            decision = await engine.evaluate(
                decision_point="data.cognic.supply_chain.allow",
                input={
                    "attestation_grade": "partial",
                    "tenant_policy": {"require_full": True},
                },
            )
        assert decision.allow is False


# ---------------------------------------------------------------------------
# TestDefaultPluginAllowlist — JSON validity + documented shape.
# Registry consumption lands in T5; this test just ensures the file is
# valid JSON with the documented top-level structure so T5 doesn't
# need to discover it the hard way.
# ---------------------------------------------------------------------------


class TestDefaultPluginAllowlist:
    def test_real_allowlist_file_exists(self) -> None:
        assert _REAL_ALLOWLIST.is_file(), f"default plugin allow-list missing at {_REAL_ALLOWLIST}"

    def test_real_allowlist_is_valid_json(self) -> None:
        data = json.loads(_REAL_ALLOWLIST.read_text())
        assert isinstance(data, dict), (
            "allow-list root must be an object: {tenant_id: [pack_name, ...]}"
        )

    def test_default_tenant_present(self) -> None:
        """Sprint-4 plan §6: ``_default`` is the placeholder tenant
        used when a deployment hasn't configured per-tenant overrides.
        The cognic_test_pack fixture (T12) is the single allow-listed
        pack at Sprint 4 — production deployments overwrite or swap
        to a Vault-backed list at Sprint 10."""
        data = json.loads(_REAL_ALLOWLIST.read_text())
        assert "_default" in data
        assert isinstance(data["_default"], list)
        assert "cognic_test_pack" in data["_default"]
