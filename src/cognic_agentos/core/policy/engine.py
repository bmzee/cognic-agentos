"""Minimal Rego evaluator seed (Sprint 4, per ADR-015).

Layer: **platform primitive** (critical control per AGENTS.md —
admission-control substrate; ≥95% line / ≥90% branch coverage gate
enforced by ``tools/check_critical_coverage.py`` after T15).

Sprint 4 ships the smallest evaluator that can answer
``policies/_default/supply_chain.rego`` per ADR-015 §"Sprint 4 (seed)":

  - Embeds the OPA Go binary; subprocess-based invocation
  - Loads bundles from disk only (no hot-reload — Sprint 13.5)
  - Audit: emits ``policy.bundle_loaded`` once at engine load and
    ``policy.decision_evaluated`` per ``evaluate()`` call; both are
    hash-chained into ``decision_history`` per Sprint-4 plan §7

Secure-subprocess invariants per Sprint-4 plan §2 + §5:

  1. **Argv is list-form only.** ``shell=False`` is explicit and
     tested by ``TestEvaluate.test_subprocess_argv_is_list_form_no_shell``.
  2. **OPA path is resolved at first use** via
     ``shutil.which("opa")`` if the operator did not pin one in
     ``Settings.opa_path``. Missing OPA at construction skips the
     bundle-syntax check (lazy) so a kernel-only image can still
     instantiate ``OPAEngine``; missing OPA at ``evaluate()`` raises
     ``OpaNotInstalledError`` fail-closed.
  3. **No pack-controlled string ever flows into argv.** The
     ``decision_point`` query string is a compile-time constant from
     the calling module; ``input`` is JSON-serialised via
     ``canonical_bytes`` (deterministic) and piped through stdin.
  4. **Explicit minimal env.** Subprocess receives only ``PATH`` and
     ``HOME``; never ``os.environ`` passthrough.
  5. **Strict timeout.** ``eval_timeout_s`` (default 5s) bounds each
     ``evaluate()``; ``subprocess.TimeoutExpired`` → SIGKILL +
     ``RegoEvaluationError``. The ``opa fmt`` syntax check at
     construction uses a separate hard-coded 30s ceiling.
  6. **JSON output parse only.** ``opa eval --format json``; never
     a regex over free-form stderr. Parse failure / non-zero exit /
     empty result / non-boolean expression value → fail-closed
     ``RegoEvaluationError``.

Async ``OPAEngine.create()`` factory exists because
``policy.bundle_loaded`` emission is async (Sprint 2 substrate is
async); the sync ``__init__`` cannot await. Construction shape:
``__init__`` does sync work (bundle read + sha256 + opa-resolve +
optional syntax-check); ``create()`` is the public async constructor
that calls ``__init__`` then emits ``policy.bundle_loaded``.

References:
- ADR-015 (policy-as-code)
- Sprint-4 plan-of-record §5 (engine seed) + §7 (first
  decision_history emissions; critical-controls discipline)
- AGENTS.md critical-controls list
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import logging
import math
import shutil
import subprocess
from pathlib import Path
from typing import Any

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

_LOG = logging.getLogger("cognic_agentos.core.policy.engine")

#: Hard ceiling for the bundle-syntax-check subprocess at engine
#: construction. Distinct from ``eval_timeout_s`` because the syntax
#: check runs once per engine lifetime + needs more headroom for a
#: cold OPA start than the steady-state per-evaluate timeout.
_BUNDLE_SYNTAX_CHECK_TIMEOUT_S: float = 30.0

#: Minimal env for every OPA subprocess invocation per §2 invariant 5.
#: PATH is needed so OPA's own subprocess-y bits (rare; mostly self-
#: contained Go binary) resolve cleanly; HOME is set to /tmp to keep
#: any incidental cache writes off the AgentOS service-account home.
_MINIMAL_SUBPROCESS_ENV: dict[str, str] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}


# ---------------------------------------------------------------------------
# Exceptions — fail-closed taxonomy for the evaluator surface.
# ---------------------------------------------------------------------------


class OpaNotInstalledError(RuntimeError):
    """Raised when the OPA Go binary cannot be located.

    At engine construction, this is silently downgraded (the syntax
    check is skipped — kernel-only-image scenario). At ``evaluate()``
    time, raises hard.
    """


class RegoBundleNotFoundError(FileNotFoundError):
    """Raised when the configured bundle path does not exist on disk."""


class RegoBundleInvalidError(ValueError):
    """Raised when ``opa fmt --diff`` reports the bundle has invalid Rego.

    Only fires when OPA is available at construction time. When OPA is
    unavailable at construction, syntax validation is deferred — the
    bundle's bytes are still hashed + ``policy.bundle_loaded`` is still
    emitted; the first ``evaluate()`` call will surface any error via
    ``RegoEvaluationError`` instead.
    """


class RegoEvaluationError(RuntimeError):
    """Raised when ``evaluate()`` cannot return a clean ``Decision``.

    Covers: subprocess non-zero exit, malformed JSON output, OPA
    ``TimeoutExpired``, empty result set (decision_point not found),
    non-boolean expression value at the result root.
    """


# ---------------------------------------------------------------------------
# Decision dataclass — Sprint-4 §5 / §8 (Q8 lock).
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of one ``OPAEngine.evaluate()`` call.

    Per Sprint-4 plan §5/§8 (Q8 lock): ``decision_data`` carries
    Sprint-specific structured outcomes (e.g. ``{"attestation_grade":
    "full"}`` for the supply-chain bundle). Downstream callers consume
    ``decision_data`` for rich outcomes rather than overloading
    ``rule_matched`` / ``reasoning``. ADR-015's documented sync API
    is ``{allow, rule_matched, reasoning}``; the Sprint-4 seed extends
    that shape with the optional ``decision_data`` slot to avoid an
    API break when Sprint 13.5 adds richer decision points.
    """

    allow: bool
    rule_matched: str | None
    reasoning: str
    decision_data: dict[str, Any] | None


# ---------------------------------------------------------------------------
# OPAEngine — load-from-disk Rego evaluator seed.
# ---------------------------------------------------------------------------


class OPAEngine:
    """Sprint-4 minimal Rego evaluator seed.

    Construction loads + hashes the bundle and resolves the OPA
    binary; the async ``create()`` factory additionally emits
    ``policy.bundle_loaded`` into ``decision_history``. Every
    ``evaluate()`` call shells out to OPA via secure subprocess and
    emits ``policy.decision_evaluated``.

    Public surface:
      - ``OPAEngine(*, bundle_path, audit_store, decision_history_store,
        opa_path=None, eval_timeout_s=5.0)`` — sync constructor
      - ``OPAEngine.create(...)`` — async classmethod that wraps
        construction + ``policy.bundle_loaded`` emission
      - ``await engine.evaluate(*, decision_point, input)`` —
        per-call evaluation
      - ``engine.bundle_sha256`` — hex digest of the loaded bundle

    Both ``audit_store`` and ``decision_history_store`` are injected
    even though only the latter is consumed by the Sprint-4 seed; the
    audit-store slot is reserved for any future internal audit emissions
    (e.g. timeout-was-hit warnings) that don't carry decision-history
    semantics.
    """

    def __init__(
        self,
        *,
        bundle_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        opa_path: str | None = None,
        eval_timeout_s: float = 5.0,
    ) -> None:
        if not (math.isfinite(eval_timeout_s) and eval_timeout_s > 0):
            # R2 reviewer-P2 §2 + R3 reviewer-P2 §2: even though
            # ``Settings.opa_eval_timeout_s`` has gt=0.0 validation,
            # OPAEngine is a directly-constructable critical-control
            # primitive — same pattern that bit Sprint-3 T7. The
            # finite-positive check is mandatory: ``float("nan")`` and
            # ``float("inf")`` both pass a bare ``> 0`` check but
            # disable subprocess.run's timeout enforcement (NaN
            # comparisons are False; infinity is unbounded). Without
            # ``math.isfinite``, a hostile / careless caller can
            # silently disable the §5 strict-timeout invariant.
            raise ValueError(f"eval_timeout_s must be finite and > 0; got {eval_timeout_s!r}")
        if not bundle_path.is_file():
            raise RegoBundleNotFoundError(f"Rego bundle not found at {bundle_path!s}")
        bundle_bytes = bundle_path.read_bytes()
        self._bundle_path: Path = bundle_path
        self._bundle_sha256: str = hashlib.sha256(bundle_bytes).hexdigest()
        self._audit_store = audit_store  # reserved; see class docstring
        self._decision_history_store = decision_history_store
        self._eval_timeout_s = eval_timeout_s
        # OPA-binary resolution. The operator may pin via Settings;
        # absent that, ``shutil.which`` finds it on PATH.
        self._opa_path: str | None = opa_path or shutil.which("opa")
        if self._opa_path is not None:
            # Validate Rego syntax via ``opa fmt --diff``. Non-zero
            # exit ⇒ RegoBundleInvalidError. Subprocess shape mirrors
            # ``evaluate()``: list-form argv, shell=False, minimal env.
            self._validate_bundle_syntax()
        else:
            _LOG.warning(
                "OPA binary not found at engine construction; "
                "Rego syntax validation deferred. Calls to evaluate() "
                "will fail-closed with OpaNotInstalledError until OPA "
                "is installed. bundle=%s",
                bundle_path,
            )

    # --- Public properties ------------------------------------------------

    @property
    def bundle_sha256(self) -> str:
        """Hex digest of the loaded bundle bytes."""
        return self._bundle_sha256

    # --- Async factory ----------------------------------------------------

    @classmethod
    async def create(
        cls,
        *,
        bundle_path: Path,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        opa_path: str | None = None,
        eval_timeout_s: float = 5.0,
    ) -> OPAEngine:
        """Async factory: sync ``__init__`` + emit ``policy.bundle_loaded``.

        ADR-015 §"Engine integration" mandates emission "on bundle
        load" — implemented as: __init__ runs sync work, then create()
        awaits the decision-history append. Tests use this factory;
        production callers do too. Sync construction is exposed so
        callers that don't need the emission (e.g. config-validation
        smoke tests at startup) can still instantiate.
        """
        engine = cls(
            bundle_path=bundle_path,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            opa_path=opa_path,
            eval_timeout_s=eval_timeout_s,
        )
        await engine._emit_bundle_loaded()
        return engine

    # --- Public evaluate --------------------------------------------------

    async def evaluate(
        self,
        *,
        decision_point: str,
        input: dict[str, Any],
    ) -> Decision:
        """Evaluate ``decision_point`` against ``input`` via OPA subprocess.

        Args:
            decision_point: Compile-time-constant Rego query string
                (e.g. ``"data.cognic.supply_chain.allow"``). MUST NOT
                contain pack-controlled or user-controlled content.
            input: Decision input dict; serialised via the Sprint-2
                canonical_bytes path (deterministic) and piped through
                stdin to the OPA subprocess. Field names + values flow
                through fingerprinting only — never persisted in the
                emitted ``policy.decision_evaluated`` payload.

        Returns:
            ``Decision`` with the parsed boolean ``allow`` value plus
            ``rule_matched=decision_point`` and ``reasoning`` derived
            from the bundle's documented enum.

        Raises:
            OpaNotInstalledError: when OPA is not available at
                evaluate-time (kernel-only-image scenario or operator-
                pinned ``opa_path`` no longer points at a real binary).
            RegoEvaluationError: subprocess pathology — non-zero exit,
                JSON parse failure, ``TimeoutExpired``, empty result
                set, or non-boolean expression value.

        Evidence (R1 reviewer-P2 §1): EVERY evaluate() call emits
        exactly one ``policy.decision_evaluated`` row into
        decision_history — including all fail-closed paths, which
        emit with ``outcome="deny"`` + ``error_kind`` so an examiner
        can prove the engine was queried even when the underlying
        OPA invocation failed. The emission happens BEFORE the
        Python-level exception is raised so the chain reflects the
        admission decision regardless of the eventual exception.
        """
        # Compute input_fingerprint up-front so it's available for
        # failure-path emissions BEFORE we decide whether to continue.
        input_bytes = canonical_bytes(input)
        input_fingerprint = hashlib.sha256(input_bytes).hexdigest()

        if self._opa_path is None:
            await self._emit_decision_evaluated_failure(
                decision_point=decision_point,
                input_fingerprint=input_fingerprint,
                error_kind="opa_not_installed",
            )
            raise OpaNotInstalledError(
                "opa not found on PATH and no override path configured; "
                "cannot evaluate Rego decision"
            )

        argv = [
            self._opa_path,
            "eval",
            "--data",
            str(self._bundle_path),
            "--format",
            "json",
            "--stdin-input",
            decision_point,
        ]

        try:
            completed = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                input=input_bytes.decode("utf-8"),
                env=_MINIMAL_SUBPROCESS_ENV,
                timeout=self._eval_timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            await self._emit_decision_evaluated_failure(
                decision_point=decision_point,
                input_fingerprint=input_fingerprint,
                error_kind="timeout",
                timeout_s=self._eval_timeout_s,
            )
            raise RegoEvaluationError(
                f"OPA evaluate timeout after {self._eval_timeout_s}s "
                f"on decision_point={decision_point!r}"
            ) from exc
        except FileNotFoundError as exc:
            # R1 reviewer-P2 §2: opa_path was pinned but the binary is
            # missing on disk. Stay in the OpaNotInstalledError taxonomy
            # rather than leak FileNotFoundError to the caller.
            await self._emit_decision_evaluated_failure(
                decision_point=decision_point,
                input_fingerprint=input_fingerprint,
                error_kind="opa_not_installed",
            )
            raise OpaNotInstalledError(
                f"opa binary not found at pinned path {self._opa_path!r}; "
                "cannot evaluate Rego decision"
            ) from exc

        if completed.returncode != 0:
            # R2 reviewer-P2 §1 — privacy: persist sanitized stderr
            # fingerprint instead of raw stderr (which may carry
            # policy-controlled / input-derived text). Python-level
            # exception keeps the raw stderr for debugging.
            stderr_bytes = completed.stderr.encode("utf-8") if completed.stderr else b""
            await self._emit_decision_evaluated_failure(
                decision_point=decision_point,
                input_fingerprint=input_fingerprint,
                error_kind="non_zero_exit",
                exit_code=completed.returncode,
                stderr_sha256=hashlib.sha256(stderr_bytes).hexdigest(),
                stderr_len=len(stderr_bytes),
            )
            raise RegoEvaluationError(
                f"OPA evaluate non-zero exit {completed.returncode} "
                f"on decision_point={decision_point!r}: {completed.stderr!r}"
            )

        try:
            decision = self._parse_decision(completed.stdout, decision_point)
        except RegoEvaluationError:
            # Same privacy pattern: stdout fingerprint (not raw bytes).
            stdout_bytes = completed.stdout.encode("utf-8") if completed.stdout else b""
            await self._emit_decision_evaluated_failure(
                decision_point=decision_point,
                input_fingerprint=input_fingerprint,
                error_kind="parse_failure",
                exit_code=completed.returncode,
                stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
                stdout_len=len(stdout_bytes),
            )
            raise

        await self._emit_decision_evaluated(
            decision_point=decision_point,
            input_fingerprint=input_fingerprint,
            decision=decision,
        )
        return decision

    # --- Private helpers --------------------------------------------------

    def _validate_bundle_syntax(self) -> None:
        """Run ``opa fmt --diff`` against the bundle. Non-zero → invalid.

        R1 reviewer-P2 §2 — fail-closed taxonomy: a missing pinned
        ``opa_path`` raises ``OpaNotInstalledError`` (not the raw
        ``FileNotFoundError`` from the OS). Construction-time emissions
        do NOT happen here (no ``policy.decision_evaluated`` semantics
        for syntax-check); the operator gets a clean exception class
        and decides whether to abort startup.
        """
        assert self._opa_path is not None  # caller checked
        try:
            completed = subprocess.run(
                [self._opa_path, "fmt", "--diff", str(self._bundle_path)],
                shell=False,
                capture_output=True,
                text=True,
                env=_MINIMAL_SUBPROCESS_ENV,
                timeout=_BUNDLE_SYNTAX_CHECK_TIMEOUT_S,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RegoBundleInvalidError(
                f"OPA syntax check timeout after "
                f"{_BUNDLE_SYNTAX_CHECK_TIMEOUT_S}s on bundle "
                f"{self._bundle_path!s}"
            ) from exc
        except FileNotFoundError as exc:
            raise OpaNotInstalledError(
                f"opa binary not found at pinned path {self._opa_path!r}; "
                "cannot validate Rego bundle syntax at construction"
            ) from exc
        if completed.returncode != 0:
            raise RegoBundleInvalidError(
                f"Rego bundle has invalid syntax (opa fmt --diff exit "
                f"{completed.returncode}): {completed.stderr!r}"
            )

    @staticmethod
    def _parse_decision(stdout: str, decision_point: str) -> Decision:
        """Parse OPA's ``--format json`` output into a ``Decision``."""
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RegoEvaluationError(f"OPA returned malformed JSON: {exc.msg}") from exc
        # R3 reviewer-P2 §1: ``json.loads`` returns whatever JSON value
        # the input encodes — including list / str / int / float / bool /
        # None for syntactically-valid non-object JSON. Validate the
        # root is a dict before reading ``result`` so an unexpected
        # shape (e.g. ``"[]"`` from a misconfigured OPA) fails-closed
        # via the documented taxonomy instead of leaking AttributeError.
        if not isinstance(payload, dict):
            raise RegoEvaluationError(
                f"OPA JSON output root is not an object (got "
                f"{type(payload).__name__}); the Sprint-4 seed "
                f"evaluator only handles object-shaped responses"
            )
        result = payload.get("result", [])
        if not result:
            raise RegoEvaluationError(
                f"OPA returned empty result set for decision_point="
                f"{decision_point!r}; no rule matched"
            )
        try:
            value = result[0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RegoEvaluationError(f"OPA result shape unexpected: {exc}") from exc
        if not isinstance(value, bool):
            raise RegoEvaluationError(
                f"OPA expression value is not boolean (got "
                f"{type(value).__name__}); the Sprint-4 seed evaluator "
                f"only handles boolean allow rules"
            )
        reasoning = "rule matched: allow" if value else "rule matched: deny (default)"
        return Decision(
            allow=value,
            rule_matched=decision_point,
            reasoning=reasoning,
            decision_data=None,
        )

    async def _emit_bundle_loaded(self) -> None:
        """Emit ``policy.bundle_loaded`` into ``decision_history``."""
        record = DecisionRecord(
            decision_type="policy.bundle_loaded",
            request_id=f"engine_load_{self._bundle_sha256[:16]}",
            payload={
                "bundle_path": str(self._bundle_path),
                "bundle_sha256": self._bundle_sha256,
                "loaded_at": _dt.datetime.now(_dt.UTC).isoformat(),
            },
            iso_controls=("ISO42001.A.7.4",),
        )
        await self._decision_history_store.append(record)

    async def _emit_decision_evaluated(
        self,
        *,
        decision_point: str,
        input_fingerprint: str,
        decision: Decision,
    ) -> None:
        """Emit ``policy.decision_evaluated`` into ``decision_history``.

        Privacy: the input ITSELF is NEVER persisted in the payload —
        only ``input_fingerprint`` (sha256 of canonical_bytes(input))
        is recorded so an examiner can match the evaluation row to a
        known input replay without leaking tenant / pack identifiers
        through the immutable chain.
        """
        record = DecisionRecord(
            decision_type="policy.decision_evaluated",
            request_id=f"eval_{input_fingerprint[:16]}",
            payload={
                "decision_point": decision_point,
                "input_fingerprint": input_fingerprint,
                "outcome": "allow" if decision.allow else "deny",
                "rule_matched": decision.rule_matched,
                "bundle_sha256": self._bundle_sha256,
            },
            iso_controls=("ISO42001.A.7.4",),
        )
        await self._decision_history_store.append(record)

    async def _emit_decision_evaluated_failure(
        self,
        *,
        decision_point: str,
        input_fingerprint: str,
        error_kind: str,
        exit_code: int | None = None,
        stderr_sha256: str | None = None,
        stderr_len: int | None = None,
        stdout_sha256: str | None = None,
        stdout_len: int | None = None,
        timeout_s: float | None = None,
    ) -> None:
        """Emit ``policy.decision_evaluated`` with ``outcome="deny"`` for a
        fail-closed evaluation.

        R1 reviewer-P2 §1: every ``evaluate()`` call produces an
        admission-control decision; failures are deny-by-default and
        therefore MUST leave evidence in ``decision_history``. Without
        this, a typo in ``opa_path`` or a transient OPA crash would
        produce silent denies an examiner could not reconstruct.

        R2 reviewer-P2 §1 — privacy contract: the persisted payload
        carries ONLY engine-generated fields. Raw OPA stderr / stdout
        are external subprocess strings that may contain policy-
        controlled text, paths, or input-derived debug output —
        persisting them would break the chain's privacy claim that
        only ``input_fingerprint`` crosses the boundary. Instead, the
        payload records:

          * ``error_kind`` — closed enum (``opa_not_installed`` /
            ``timeout`` / ``non_zero_exit`` / ``parse_failure``)
          * ``exit_code`` — integer exit code from OPA, or None for
            non-subprocess errors (``opa_not_installed``)
          * ``stderr_sha256`` + ``stderr_len`` — sanitized fingerprint
            of stderr; an examiner correlates with offline replay
            without leaking content into the chain
          * ``stdout_sha256`` + ``stdout_len`` — same pattern for
            stdout (parse-failure cases where the JSON payload is
            malformed)
          * ``timeout_s`` — engine-configured timeout when the
            subprocess hit it

        The Python-level ``RegoEvaluationError`` raised after this
        emission preserves raw stderr/stdout in its message for
        application-side debugging — that text never crosses into
        decision_history.
        """
        record = DecisionRecord(
            decision_type="policy.decision_evaluated",
            request_id=f"eval_fail_{input_fingerprint[:16]}",
            payload={
                "decision_point": decision_point,
                "input_fingerprint": input_fingerprint,
                "outcome": "deny",
                "rule_matched": None,
                "bundle_sha256": self._bundle_sha256,
                "error_kind": error_kind,
                "exit_code": exit_code,
                "stderr_sha256": stderr_sha256,
                "stderr_len": stderr_len,
                "stdout_sha256": stdout_sha256,
                "stdout_len": stdout_len,
                "timeout_s": timeout_s,
            },
            iso_controls=("ISO42001.A.7.4",),
        )
        await self._decision_history_store.append(record)


__all__ = (
    "Decision",
    "OPAEngine",
    "OpaNotInstalledError",
    "RegoBundleInvalidError",
    "RegoBundleNotFoundError",
    "RegoEvaluationError",
)
