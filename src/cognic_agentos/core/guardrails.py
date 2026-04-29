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

from cognic_agentos.core.audit import AuditStore


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
        """Run the configured guardrails over ``content``. T7 wires
        the body. Until then, calling this method raises so a
        half-built pipeline can't silently accept input.
        """

        raise NotImplementedError(
            "GuardrailPipeline.check is wired in Sprint 2.5 T7; T5 ships "
            "shapes only. See docs/superpowers/plans/"
            "2026-04-29-sprint-2.5-operational-primitives.md."
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

    name: ClassVar[str] = "pii.regex.baseline"

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

    name: ClassVar[str] = "injection.regex.baseline"

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
