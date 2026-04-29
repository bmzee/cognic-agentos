"""Pluggable guardrail filter pipeline — input/output content
checks against PII, prompt-injection, and other pack-supplied
signals. Trips emit ``audit_event`` rows via Sprint 2's
``AuditStore``.

**Critical-controls module.** Per AGENTS.md + the Sprint 2.5 plan-
of-record (PR #7 / commit ``4733b52``): ≥95% line + ≥90% branch
coverage; halt-before-commit per edit. T5 lands the SHAPES (this
file); T6 lands the bundled regex filters; T7 wires the pipeline
body + audit emission.

Layered design:

  - ``Guardrail`` — runtime-checkable Protocol that any pack-
    supplied filter conforms to structurally. Just ``name: str``
    + ``check(content) -> GuardrailResult``. No async required;
    each individual filter runs sync per-row, and the pipeline
    aggregates the results before any I/O.
  - ``GuardrailResult`` — frozen+slotted per-guardrail result.
    Carries the trip outcome (``passed: bool``), the named
    pattern matches (NOT raw matched text — preserving evidence
    privacy), and a free-form diagnostic ``detail`` string.
  - ``PipelineResult`` — frozen+slotted aggregate over the
    pipeline's results. ``passed`` is True iff every constituent
    guardrail passed.
  - ``GuardrailPipeline`` — runs the configured guardrails
    unconditionally (no short-circuit on first trip — auditors
    want the full picture: "input matched both PII AND injection
    patterns"); on any trip emits one ``AuditEvent`` per tripped
    guardrail through the supplied ``AuditStore``. T5 ships the
    constructor; T7 wires the body.

Decoupling rationale: the Protocol-based shape lets pack-supplied
filters land as plain classes (no inheritance, no registration
ceremony). The pipeline is the single mediator that knows about
``AuditStore`` and the trip-emission contract; individual
guardrails are pure functions over content.

PII privacy: ``GuardrailResult.matches`` carries diagnostic
**pattern names** (e.g. ``"credit_card"``, ``"ssn_us"``), NOT the
matched text. Round-tripping raw matches into the chain would
recreate the very data the filter was meant to block. Pack
contracts enforcing match-text emission for explicit cases (e.g.
debugging) are explicitly out of Sprint-2.5 scope.
"""

from __future__ import annotations

import dataclasses
import re
from enum import StrEnum
from typing import ClassVar, Protocol, runtime_checkable

from cognic_agentos.core.audit import AuditEvent, AuditStore


class GuardrailDirection(StrEnum):
    """Direction of the content under inspection. ``INPUT`` is
    pre-LLM-call (or pre-tool-invocation); ``OUTPUT`` is post-
    response-generation. The pipeline runs separately for each
    direction; the same set of filters can be configured for both
    or just one. StrEnum so the value round-trips through canonical-
    form serialisation per Sprint 2 R3."""

    INPUT = "input"
    OUTPUT = "output"


@dataclasses.dataclass(frozen=True, slots=True)
class GuardrailResult:
    """Per-guardrail result.

    Frozen + slotted: safe to share across coroutines + immune to
    after-the-fact mutation that would silently alter aggregated
    pipeline results.

    Attributes:
        guardrail_name: Stable identifier from ``Guardrail.name`` —
            mirrored here for convenience so ``PipelineResult.results``
            consumers don't need a parallel name lookup.
        passed: ``True`` iff the guardrail did not trip on the
            supplied content. ``False`` means a pattern matched.
        matches: Tuple of named patterns the guardrail matched. NOT
            raw matched text (PII privacy — see module docstring).
            Empty tuple when ``passed=True``.
        detail: Optional free-form diagnostic string for human
            readers. Programmatic consumers branch on ``passed`` +
            ``matches``.
    """

    guardrail_name: str
    passed: bool
    matches: tuple[str, ...] = ()
    detail: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class PipelineResult:
    """Aggregate result across the whole pipeline.

    Attributes:
        direction: Which side the pipeline ran for (input vs output).
            Mirrored from the ``check()`` keyword argument so callers
            don't need to plumb it separately.
        passed: ``True`` iff every constituent guardrail passed.
            False means at least one guardrail tripped — the caller's
            request-path policy (block, sanitise, escalate) decides
            the response.
        results: Per-guardrail results, in the same order the
            pipeline was constructed with. Tuple — immutable, safe
            to share.
    """

    direction: GuardrailDirection
    passed: bool
    results: tuple[GuardrailResult, ...]


@runtime_checkable
class Guardrail(Protocol):
    """Structural Protocol for a single content filter. Any pack-
    supplied class with ``name: str`` + ``check(content) -> GuardrailResult``
    conforms; ``isinstance(x, Guardrail)`` is the runtime check.

    The Protocol is sync (``check`` returns a result, not an
    awaitable) because each filter is a per-row pure function over
    the content. The pipeline composes filters sync and only
    becomes async at the audit-emission boundary (T7).
    """

    name: str

    def check(self, content: str) -> GuardrailResult: ...


class GuardrailPipeline:
    """Run an ordered sequence of guardrails over ``content``.

    T5 (this file): constructor stores guardrails + audit_store
    references; ``check()`` is a placeholder that raises
    ``NotImplementedError`` until T7 wires the body. T6 ships the
    bundled regex filters that callers configure into the pipeline.
    T7 wires:

      - Run every guardrail unconditionally (no short-circuit on
        first trip — auditors want the full picture).
      - Aggregate per-guardrail ``GuardrailResult`` into a
        ``PipelineResult``.
      - For each tripped guardrail, emit one ``AuditEvent`` via
        the supplied ``AuditStore`` with ``event_type="guardrail.trip"``,
        the guardrail name + matched-pattern names + direction in
        the payload, and ``iso_controls=("ISO42001.A.7.4",)``.
        Fail-loud emission posture mirrors ``AuditStore.append``
        (Sprint 2 R3) — if the audit emit raises, ``check()``
        raises; the request-path caller decides whether to block,
        retry, or surface a 5xx.
    """

    def __init__(
        self,
        guardrails: tuple[Guardrail, ...],
        audit_store: AuditStore,
    ) -> None:
        self._guardrails = guardrails
        self._audit_store = audit_store

    async def check(
        self,
        content: str,
        *,
        direction: GuardrailDirection,
        request_id: str,
        tenant_id: str | None = None,
    ) -> PipelineResult:
        """Run the configured guardrails over ``content`` + emit one
        ``audit_event`` per tripped guardrail.

        Order of operations:

          1. Run every guardrail synchronously over ``content``.
             No short-circuit on first trip — auditors want the full
             picture (e.g. "input matched both PII AND injection
             patterns").
          2. Aggregate per-guardrail ``GuardrailResult`` into the
             ``PipelineResult`` shape; ``passed`` is True iff every
             constituent guardrail passed.
          3. For each tripped guardrail, emit ONE
             ``AuditEvent`` via the supplied ``AuditStore``. One
             audit row per trip (NOT per pipeline run) so the chain
             carries diagnostic granularity. Emission order matches
             pipeline order: chain sequence == pipeline position for
             trips in a single check() call.
          4. Return the aggregated ``PipelineResult``.

        Audit-emission shape:

          - ``event_type``: ``"guardrail.trip"`` (canonical chain
            discriminator for guardrail emissions).
          - ``request_id``: caller-supplied; ties the trip back to
            the originating request.
          - ``tenant_id``: caller-supplied; carried through for
            Wave-2 multi-tenant policy enforcement.
          - ``payload``: dict with ``guardrail_name``, ``direction``,
            and ``matches`` (list — canonical-form snapshot of the
            tuple from ``GuardrailResult.matches``).
            **PII privacy:** ``matches`` is the named-pattern tuple
            from T6 filters, NEVER raw matched text. The pipeline
            INTENTIONALLY does NOT persist ``GuardrailResult.detail``
            into the audit payload — ``detail`` is free-form text
            from arbitrary ``Guardrail`` implementations, and a pack-
            supplied filter could legitimately put raw matched text
            (PII, debug context) in there. Persisting that into the
            immutable chain would defeat the T5/T6 privacy contract.
            ``detail`` stays on the in-process ``GuardrailResult``
            for caller-side diagnostics that DON'T cross into
            evidence. (T7-reviewer-P1 fix.)
          - ``iso_controls``: ``("ISO42001.A.7.4",)`` — the AI
            system risk-control mapping for guardrail trips.

        Fail-loud emission posture: if ``AuditStore.append`` raises,
        ``check`` raises. Mirrors Sprint 2 R3 fail-loud: the request-
        path caller (LLM gateway, harness) decides whether to block
        the request, retry the audit, or surface a 5xx. The pipeline
        does NOT silently swallow audit failures — that would let a
        guardrail trip slip through without evidence, defeating the
        entire purpose of the chain.

        Note on emission ordering vs pipeline aggregation: trips are
        accumulated first (step 2), then emitted in a separate loop
        (step 3). This means a fail-loud audit failure on the FIRST
        emission still propagates with the per-guardrail
        ``GuardrailResult`` set already aggregated — but no
        ``PipelineResult`` is returned (the exception cuts out before
        step 4). That's the correct posture: the caller sees the
        emission failure, not a partial result.
        """

        results = tuple(g.check(content) for g in self._guardrails)
        passed = all(r.passed for r in results)

        for r in results:
            if r.passed:
                continue
            await self._audit_store.append(
                AuditEvent(
                    event_type="guardrail.trip",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    # NOTE: ``GuardrailResult.detail`` is INTENTIONALLY
                    # excluded — it's free-form text from arbitrary
                    # filter implementations that could leak raw
                    # matched PII into the immutable chain. See the
                    # method docstring's ``payload`` section for the
                    # T7-reviewer-P1 rationale.
                    payload={
                        "guardrail_name": r.guardrail_name,
                        "direction": direction.value,
                        "matches": list(r.matches),
                    },
                    iso_controls=("ISO42001.A.7.4",),
                )
            )

        return PipelineResult(
            direction=direction,
            passed=passed,
            results=results,
        )


# ===========================================================================
# Sprint 2.5 T6 — bundled regex filters
# ===========================================================================
#
# Per BUILD_PLAN: regex-based MVP. ML-based intent classification +
# semantic PII detection are explicitly Wave 2. The intentional
# false-positive bias is correct for Sprint 2.5: a high-recall filter
# at the perimeter is the right shape for ISO 42001 evidence; pack-
# side overrides + downstream gates can refine.
#
# PII privacy: each filter's GuardrailResult.matches carries pattern
# NAMES (e.g. "credit_card"), NEVER raw matched text. The pipeline
# emits these names into audit_event payloads (T7); round-tripping
# raw matches into the chain would recreate the data the filter was
# meant to block.


class RegexPIIGuardrail:
    """Sprint-2.5 baseline PII filter. Detects rough patterns for:

      - Credit cards (Luhn-light: 13-19 digits, optional separators).
      - US SSN-shape (NNN-NN-NNNN).
      - Phone-number-shape (+? 10-15 digits with optional separators).
      - Email addresses (RFC-5322-light).

    High-recall by design — false-positives at the perimeter are
    acceptable; downstream gates can refine. Conforms to the
    ``Guardrail`` Protocol (``name: str`` + ``check(content) ->
    GuardrailResult``).
    """

    # ``name`` is a plain class attribute (immutable str — no RUF012
    # mutable-default flag) and is also the Protocol-required
    # instance variable (mypy treats class-level str assignment as
    # matching ``name: str`` on the Protocol). ``_PATTERNS`` is
    # genuinely shared mutable-default-ish state, so it gets
    # ClassVar to satisfy RUF012.
    name: str = "pii.regex.baseline"

    _PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        # Credit card: 13-19 digits, optionally interleaved with
        # single space or hyphen. \b boundaries keep us from gluing
        # to surrounding digits.
        "credit_card": re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        # US SSN shape: NNN-NN-NNNN. Anchored to word boundaries.
        "ssn_us": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        # Phone: optional + prefix, then 10-15 digits with optional
        # separators (space, hyphen, parens) interspersed between
        # adjacent digits. Strict total-digit count:
        # ``(?:\d[ \-()]{0,2}){9,14}\d`` is 9-14 (digit + ≤2 sep)
        # iterations + a final digit, so exactly 10-15 total digits.
        # Non-word/non-digit lookbehind/lookahead reject any
        # surrounding alphanumeric so the pattern does NOT trip on
        # short numeric IDs (≤9 digits) or naked long sequences
        # (≥16 digits — e.g. naked credit cards or order IDs).
        # The earlier ``\d{1,3}...\d{2,9}`` shape was 7-20 digits —
        # beyond the documented range — and produced noisy phone
        # trips on short / long numeric IDs and naked CCs.
        # (T6-reviewer-P1 fix: tighten to documented 10-15.)
        #
        # Documented residual overlap: separator-formatted 16-digit
        # credit cards (e.g. ``4111-1111-1111-1111``) still trip
        # via their 12-digit phone-shaped prefix — the lookahead
        # succeeds at the position before a hyphen. This is the
        # high-recall design boundary; pinned by the corresponding
        # T6 test.
        "phone": re.compile(r"(?<![\w\d])\+?(?:\d[ \-()]{0,2}){9,14}\d(?![\w\d])"),
        # Email: RFC-5322-light. \w+ before @, dotted host after.
        "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    }

    def check(self, content: str) -> GuardrailResult:
        matches = tuple(
            sorted(pat_name for pat_name, pat in self._PATTERNS.items() if pat.search(content))
        )
        return GuardrailResult(
            guardrail_name=self.name,
            passed=not matches,
            matches=matches,
            detail=None if not matches else f"{len(matches)} pattern(s) tripped",
        )


class InjectionGuardrail:
    """Sprint-2.5 baseline prompt-injection filter. Detects:

      - Instruction-override phrasing ("ignore previous instructions"
        and variations).
      - System-prompt prefix attempts (``system:`` or
        ``system prompt:`` at line start).
      - Token-injection markers (``<|im_start|>``, ``<|endoftext|>``,
        ``### system`` at line start).

    High-recall by design. Pack-side overrides (later sprints) can
    relax. ML-based intent classification is Wave 2. Conforms to the
    ``Guardrail`` Protocol.
    """

    name: str = "injection.regex.baseline"

    _PATTERNS: ClassVar[dict[str, re.Pattern[str]]] = {
        # "ignore [all] previous instructions" — verb forms ignore /
        # ignoring, optional 'all', singular or plural 'instruction'.
        "instruction_override": re.compile(
            r"\bignor(?:e|ing)\s+(?:all\s+)?previous\s+instructions?\b",
            re.IGNORECASE,
        ),
        # "system:" or "system prompt:" at start-of-line. Catches
        # prompts that try to inject a fake system message.
        "system_prefix": re.compile(
            r"(?:^|\n)\s*system\s*(?:prompt)?\s*:",
            re.IGNORECASE,
        ),
        # Token-injection markers. ChatML-style <|im_start|> /
        # <|endoftext|> + the markdown-ish "### system" header.
        "token_injection_markers": re.compile(
            r"(?:<\|im_start\|>|<\|endoftext\|>|^###\s*system)",
            re.IGNORECASE | re.MULTILINE,
        ),
    }

    def check(self, content: str) -> GuardrailResult:
        matches = tuple(
            sorted(pat_name for pat_name, pat in self._PATTERNS.items() if pat.search(content))
        )
        return GuardrailResult(
            guardrail_name=self.name,
            passed=not matches,
            matches=matches,
            detail=None if not matches else f"{len(matches)} pattern(s) tripped",
        )


__all__: tuple[str, ...] = (
    "Guardrail",
    "GuardrailDirection",
    "GuardrailPipeline",
    "GuardrailResult",
    "InjectionGuardrail",
    "PipelineResult",
    "RegexPIIGuardrail",
)
