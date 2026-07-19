"""A-007 skill evaluation metrics and evidence joins.

The deployed runner glue builds on the existing ADR-010 ``EvalRunner``. This
module owns the skill-specific verdict matrix and gate math so repetitions,
ablation pairs, and non-gating performance checks cannot silently change their
denominators.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
import time
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.evaluation.corpus import Corpus, EvalCase, validate_corpus_payload
from cognic_agentos.evaluation.runner import EvalRunner
from cognic_agentos.evaluation.scorers import AssertionScorer
from cognic_agentos.evaluation.skill_corpus import (
    SkillCaseKind,
    SkillCorpus,
    SkillCorpusCase,
    expected_route,
)
from cognic_agentos.evaluation.types import (
    CandidateOutput,
    CriterionDetail,
    ScorerResult,
)
from cognic_agentos.portal.api.evaluation.dto import JudgeVerdictResponse

SkillEvalVariant = Literal["with_skill", "without_skill"]
SkillEvalRunRefusalReason = Literal["skill_eval_judge_calibration_missing"]

_CLASS_ORDER: tuple[SkillCaseKind, ...] = (
    "golden",
    "adversarial",
    "refusal",
    "trigger_pos",
    "trigger_neg",
)
_HARD_KINDS: frozenset[SkillCaseKind] = frozenset({"adversarial", "refusal"})
_ANSWER_KINDS: frozenset[SkillCaseKind] = frozenset({"golden", "adversarial"})
_TRIGGER_KINDS: frozenset[SkillCaseKind] = frozenset({"trigger_pos", "trigger_neg"})
_MARKDOWN_SEPARATOR = re.compile(r":?-{3,}:?\Z")
_NUMERIC_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.,])(?:[$\u00a3\u20ac]\s*)?"
    r"(?P<number>[+-]?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?)"
    r"(?P<percent>\s*%)?(?![A-Za-z0-9_]|[.,]\d|%)"
)
_EMPTY_RESULT_MARKERS: tuple[str, ...] = (
    "no rows",
    "no records",
    "no results",
    "none found",
    "zero rows",
    "0 rows",
)


def _routes_to_judge(case: SkillCorpusCase) -> bool:
    """Return whether the case will be graded by the LLM judge.

    The scorer and calibration preflight share this sole authority so a
    routing change cannot silently create an uncalibrated judge path.
    """
    return case.scoring == "judge" or case.expected.mode in {
        "refusal",
        "assumption",
        "clarify",
    }


class SkillEvalContractError(ValueError):
    """The evaluator could not prove a complete, non-duplicated matrix."""


class SkillEvalRunRefused(SkillEvalContractError):
    """Fail-closed run refusal with a closed, examiner-visible reason."""

    def __init__(self, reason: SkillEvalRunRefusalReason) -> None:
        super().__init__(reason)
        self.reason: SkillEvalRunRefusalReason = reason


@dataclasses.dataclass(frozen=True, slots=True)
class SkillCaseVerdict:
    case_id: str
    kind: SkillCaseKind
    repetition: int
    variant: SkillEvalVariant
    passed: bool
    errored: bool
    shape_passed: bool | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class WilsonInterval:
    lower: float
    upper: float


@dataclasses.dataclass(frozen=True, slots=True)
class SkillClassMetric:
    kind: SkillCaseKind
    total: int
    passed: int
    failed: int
    errored: int
    interval: WilsonInterval
    case_clusters_total: int
    case_clusters_passed: int
    case_cluster_interval: WilsonInterval


@dataclasses.dataclass(frozen=True, slots=True)
class PerformanceConformanceMetric:
    total: int
    passed: int
    rate: float | None


@dataclasses.dataclass(frozen=True, slots=True)
class SkillGateReport:
    skill_id: str
    corpus_case_count: int
    n_reps: int
    judge_model_alias: str
    judge_calibration_set_id: str
    measured_judge_kappa: float | None
    minimum_judge_kappa: float
    holdout_case_ids: tuple[str, ...]
    passed: bool
    hard_zero_observed: bool
    trigger_accuracy: float
    trigger_passed: bool
    accuracy: float
    wrong_answer_rate: float
    golden_accuracy: float
    golden_all_correct: bool
    golden_failure_case_ids: tuple[str, ...]
    ablation_uplift: float
    ablation_passed: bool
    performance_conformance: PerformanceConformanceMetric
    class_metrics: tuple[SkillClassMetric, ...]
    failure_case_ids: tuple[str, ...]


def wilson_interval(passed: int, total: int, *, z: float = 1.959963984540054) -> WilsonInterval:
    """Two-sided Wilson score interval for a binomial pass rate."""
    if total < 1 or passed < 0 or passed > total:
        raise ValueError("passed/total is outside the binomial domain")
    proportion = passed / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    centre = (proportion + z2 / (2.0 * total)) / denominator
    radius = (
        z
        * math.sqrt(proportion * (1.0 - proportion) / total + z2 / (4.0 * total * total))
        / denominator
    )
    return WilsonInterval(lower=max(0.0, centre - radius), upper=min(1.0, centre + radius))


def _verdict_index(
    corpus: SkillCorpus, verdicts: Iterable[SkillCaseVerdict]
) -> dict[tuple[str, int, SkillEvalVariant], SkillCaseVerdict]:
    variants: tuple[SkillEvalVariant, ...] = (
        ("with_skill", "without_skill") if corpus.manifest.ablation.enabled else ("with_skill",)
    )
    expected = {
        (case.case_id, repetition, variant)
        for case in corpus.cases
        for repetition in range(1, corpus.manifest.n_reps + 1)
        for variant in variants
    }
    by_case = corpus.case_by_id
    actual: dict[tuple[str, int, SkillEvalVariant], SkillCaseVerdict] = {}
    for verdict in verdicts:
        key = (verdict.case_id, verdict.repetition, verdict.variant)
        case = by_case.get(verdict.case_id)
        if case is None or verdict.kind != case.kind or key in actual:
            raise SkillEvalContractError("verdict matrix mismatch")
        actual[key] = verdict
    if set(actual) != expected:
        raise SkillEvalContractError("verdict matrix mismatch")
    return actual


def _rate(rows: list[SkillCaseVerdict]) -> float:
    return sum(row.passed and not row.errored for row in rows) / len(rows) if rows else 0.0


def compute_skill_gate(
    corpus: SkillCorpus, verdicts: Iterable[SkillCaseVerdict]
) -> SkillGateReport:
    """Compute the A-007 verdict over an exact repetitions x ablation matrix."""
    index = _verdict_index(corpus, verdicts)
    with_skill = [row for key, row in index.items() if key[2] == "with_skill"]

    class_metrics: list[SkillClassMetric] = []
    for kind in _CLASS_ORDER:
        rows = [row for row in with_skill if row.kind == kind]
        passed = sum(row.passed and not row.errored for row in rows)
        errored = sum(row.errored for row in rows)
        rows_by_case = {
            case_id: [row for row in rows if row.case_id == case_id]
            for case_id in {row.case_id for row in rows}
        }
        case_clusters_passed = sum(
            all(row.passed and not row.errored for row in case_rows)
            for case_rows in rows_by_case.values()
        )
        class_metrics.append(
            SkillClassMetric(
                kind=kind,
                total=len(rows),
                passed=passed,
                failed=len(rows) - passed - errored,
                errored=errored,
                interval=wilson_interval(passed, len(rows)),
                case_clusters_total=len(rows_by_case),
                case_clusters_passed=case_clusters_passed,
                case_cluster_interval=wilson_interval(case_clusters_passed, len(rows_by_case)),
            )
        )

    hard_rows = [row for row in with_skill if row.kind in _HARD_KINDS]
    hard_zero_observed = all(row.passed and not row.errored for row in hard_rows)

    trigger_rows = [row for row in with_skill if row.kind in _TRIGGER_KINDS]
    trigger_accuracy = _rate(trigger_rows)
    trigger_passed = trigger_accuracy >= corpus.manifest.gates.minimum_trigger_accuracy and not any(
        row.errored for row in trigger_rows
    )

    answer_rows = [row for row in with_skill if row.kind in _ANSWER_KINDS]
    accuracy = _rate(answer_rows)
    wrong_answer_rate = 1.0 - accuracy

    golden_rows = [row for row in with_skill if row.kind == "golden"]
    golden_accuracy = _rate(golden_rows)
    golden_all_correct = all(row.passed and not row.errored for row in golden_rows)
    golden_failure_case_ids = tuple(
        sorted({row.case_id for row in golden_rows if row.errored or not row.passed})
    )

    non_trigger_ids = {case.case_id for case in corpus.cases if case.kind not in _TRIGGER_KINDS}
    with_ablation = [row for row in with_skill if row.case_id in non_trigger_ids]
    if corpus.manifest.ablation.enabled:
        without_ablation = [
            row
            for key, row in index.items()
            if key[2] == "without_skill" and row.case_id in non_trigger_ids
        ]
        ablation_uplift = _rate(with_ablation) - _rate(without_ablation)
        ablation_passed = ablation_uplift >= corpus.manifest.ablation.minimum_uplift and not any(
            row.errored for row in without_ablation
        )
    else:
        ablation_uplift = 0.0
        ablation_passed = True

    shape_ids = set(corpus.manifest.performance_conformance.non_gating_case_ids)
    shape_rows = [row for row in with_skill if row.case_id in shape_ids]
    shape_passed = sum(row.shape_passed is True for row in shape_rows)
    performance_conformance = PerformanceConformanceMetric(
        total=len(shape_rows),
        passed=shape_passed,
        rate=shape_passed / len(shape_rows) if shape_rows else None,
    )

    any_with_skill_error = any(row.errored for row in with_skill)
    passed = all(
        (
            hard_zero_observed,
            trigger_passed,
            golden_all_correct,
            ablation_passed,
            not any_with_skill_error,
        )
    )
    failure_case_ids = tuple(
        sorted({row.case_id for row in with_skill if row.errored or not row.passed})
    )
    return SkillGateReport(
        skill_id=corpus.manifest.skill_id,
        corpus_case_count=len(corpus.cases),
        n_reps=corpus.manifest.n_reps,
        judge_model_alias=corpus.manifest.judge.model_alias,
        judge_calibration_set_id=corpus.manifest.judge.calibration_set_id,
        measured_judge_kappa=corpus.manifest.judge.measured_kappa,
        minimum_judge_kappa=corpus.manifest.gates.minimum_judge_kappa,
        holdout_case_ids=corpus.manifest.holdouts.case_ids,
        passed=passed,
        hard_zero_observed=hard_zero_observed,
        trigger_accuracy=trigger_accuracy,
        trigger_passed=trigger_passed,
        accuracy=accuracy,
        wrong_answer_rate=wrong_answer_rate,
        golden_accuracy=golden_accuracy,
        golden_all_correct=golden_all_correct,
        golden_failure_case_ids=golden_failure_case_ids,
        ablation_uplift=ablation_uplift,
        ablation_passed=ablation_passed,
        performance_conformance=performance_conformance,
        class_metrics=tuple(class_metrics),
        failure_case_ids=failure_case_ids,
    )


def read_skill_ids_from_dispatches(
    dispatches: Iterable[Mapping[str, object]], *, candidate_skill_ids: Iterable[str]
) -> tuple[str, ...]:
    """Join digest-only ``read_skill`` rows to known skill ids exactly."""
    candidates = tuple(candidate_skill_ids)
    if len(candidates) != len(set(candidates)):
        raise SkillEvalContractError("candidate skill ids are duplicated")
    by_digest = {
        hashlib.sha256(canonical_bytes({"skill_id": skill_id})).hexdigest(): skill_id
        for skill_id in candidates
    }
    matched: list[tuple[int, str]] = []
    for row in dispatches:
        sequence = row.get("sequence")
        digest = row.get("args_sha256")
        if (
            type(sequence) is int
            and row.get("capability_kind") == "builtin"
            and row.get("capability_ref") == "read_skill"
            and row.get("outcome") == "ok"
            and isinstance(digest, str)
            and digest in by_digest
        ):
            matched.append((sequence, by_digest[digest]))
    return tuple(skill_id for _, skill_id in sorted(matched))


def _answer_literals(value: object) -> set[str]:
    literals: set[str] = set()
    if isinstance(value, list) and value and all(isinstance(row, list) for row in value):
        for row in value:
            if len(row) == 1:
                literals.update(_answer_literals(row[0]))
                continue
            rendered = " ".join(str(cell).strip() for cell in row if cell is not None).strip()
            if rendered:
                literals.add(rendered.casefold())
        return literals
    if isinstance(value, dict) and set(value) >= {"columns", "rows"}:
        rows = value.get("rows")
        if not isinstance(rows, list):
            return literals
        for row in rows:
            if not isinstance(row, list):
                continue
            if len(row) == 1:
                literals.update(_answer_literals(row[0]))
                continue
            rendered = " ".join(str(cell).strip() for cell in row if cell is not None).strip()
            if rendered:
                literals.add(rendered.casefold())
        return literals
    if isinstance(value, str):
        text = value.strip()
        if text:
            literals.add(text.casefold())
    elif type(value) in {bool, int, float}:
        literals.add(str(value).casefold())
    elif isinstance(value, list):
        for item in value:
            literals.update(_answer_literals(item))
    elif isinstance(value, dict):
        for item in value.values():
            literals.update(_answer_literals(item))
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        if len(rendered) >= 8:
            literals.add(rendered.casefold())
    return literals


def _literal_occurs(literal: str, body: str) -> bool:
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", literal):
        return re.search(rf"(?<![\w.,]){re.escape(literal)}(?![\w]|[.,]\d)", body) is not None
    if " " in literal:
        normalized_literal = re.sub(r"[^a-z0-9.+-]+", " ", literal).strip()
        normalized_body = re.sub(r"[^a-z0-9.+-]+", " ", body)
        return normalized_literal in normalized_body
    return literal in body


def find_skill_contamination(
    pack_path: Path,
    corpus: SkillCorpus,
    *,
    reference_values: Mapping[str, object] | None = None,
) -> tuple[str, ...]:
    """Return golden case ids whose answer literals occur in ``SKILL.md``."""
    skill_path = pack_path / "SKILL.md"
    try:
        skill_body = skill_path.read_text(encoding="utf-8").casefold()
    except (OSError, UnicodeError) as exc:
        raise SkillEvalContractError("SKILL.md unavailable for contamination preflight") from exc

    contaminated: list[str] = []
    for case in corpus.cases:
        if case.kind != "golden":
            continue
        expected = (
            _expected_value(case, reference_values)
            if case.expected.verify_live and reference_values is not None
            else case.expected.value
        )
        if expected is None:
            continue
        if any(_literal_occurs(literal, skill_body) for literal in _answer_literals(expected)):
            contaminated.append(case.case_id)
    return tuple(sorted(contaminated))


def required_reference_case_ids(corpus: SkillCorpus) -> tuple[str, ...]:
    """Case ids whose expected value must be re-anchored against live SQL."""
    return tuple(
        case.case_id
        for case in corpus.cases
        if case.expected.verify_live and case.reference_sql is not None
    )


def build_eval_runner_corpus(corpus: SkillCorpus) -> Corpus:
    """Adapt the pack corpus to the existing ADR-010 ``EvalRunner`` shape."""
    return validate_corpus_payload(
        {
            "schema_version": 1,
            "corpus_id": f"skill:{corpus.manifest.skill_id}",
            "description": "A-007 skill evaluation through the conversations API",
            "cases": [
                {
                    "id": case.case_id,
                    "case_kind": "completion",
                    "messages": [{"role": "user", "content": case.question}],
                    # The existing assertion scorer owns the non-empty-answer
                    # baseline. The skill scorer below owns semantic/value truth.
                    "assertions": {"regex": [r"(?s).+"]},
                }
                for case in corpus.cases
            ],
        }
    )


@dataclasses.dataclass(frozen=True, slots=True)
class _ConversationObservation:
    answer: str
    dispatches: tuple[Mapping[str, object], ...]


class _ConversationTarget:
    target_kind = "conversation"
    tier = ""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        target_url: str,
        token: str,
        agent_id: str,
    ) -> None:
        self._client = client
        self._target_url = target_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._agent_id = agent_id
        self.observations: dict[str, _ConversationObservation] = {}

    async def run_case(self, case: EvalCase, *, request_id: str, tenant_id: str) -> CandidateOutput:
        del request_id, tenant_id
        started = time.monotonic()
        create = await self._client.post(
            f"{self._target_url}/api/v1/conversations",
            headers=self._headers,
            json={"agent_id": self._agent_id},
            follow_redirects=False,
        )
        _require_status(create, 201, operation="create_conversation")
        create_body = _mapping_body(create, operation="create_conversation")
        conversation_id = _required_uuid(create_body, "conversation_id")

        turn = await self._client.post(
            f"{self._target_url}/api/v1/conversations/{conversation_id}/turns",
            headers=self._headers,
            json={"user_message": _user_message(case)},
            follow_redirects=False,
        )
        _require_status(turn, 200, operation="post_turn")
        turn_body = _mapping_body(turn, operation="post_turn")
        answer = turn_body.get("answer")
        seq = turn_body.get("seq")
        if not isinstance(answer, str) or type(seq) is not int or seq < 1:
            raise SkillEvalContractError("post_turn response shape invalid")

        chain = await self._client.get(
            f"{self._target_url}/api/v1/conversations/{conversation_id}/turns/{seq}/chain",
            headers=self._headers,
            follow_redirects=False,
        )
        _require_status(chain, 200, operation="read_turn_chain")
        chain_body = _mapping_body(chain, operation="read_turn_chain")
        raw_dispatches = chain_body.get("dispatches")
        if not isinstance(raw_dispatches, list) or not all(
            isinstance(row, dict) for row in raw_dispatches
        ):
            raise SkillEvalContractError("turn chain dispatch shape invalid")
        dispatches = tuple(raw_dispatches)
        self.observations[case.id] = _ConversationObservation(answer=answer, dispatches=dispatches)
        return CandidateOutput(
            text=answer,
            model="",
            tier="",
            latency_ms=max(0, round((time.monotonic() - started) * 1_000)),
            outcome="succeeded",
        )


def _require_status(response: httpx.Response, expected: int, *, operation: str) -> None:
    if response.status_code != expected:
        raise SkillEvalContractError(f"{operation} failed with HTTP {response.status_code}")


def _mapping_body(response: httpx.Response, *, operation: str) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError as exc:
        raise SkillEvalContractError(f"{operation} response is not JSON") from exc
    if not isinstance(body, dict):
        raise SkillEvalContractError(f"{operation} response is not an object")
    return body


def _required_uuid(body: Mapping[str, object], key: str) -> uuid.UUID:
    value = body.get(key)
    if not isinstance(value, str):
        raise SkillEvalContractError(f"{key} is missing")
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise SkillEvalContractError(f"{key} is invalid") from exc
    if str(parsed) != value:
        raise SkillEvalContractError(f"{key} is non-canonical")
    return parsed


def _user_message(case: EvalCase) -> str:
    for message in case.messages:
        if message.role == "user":
            content = message.content
            if isinstance(content, str):
                return content
            raise SkillEvalContractError("eval user message is not text")
    raise SkillEvalContractError("eval case carries no user message")


def _normalised_reference(case: SkillCorpusCase, value: object) -> object:
    """Normalize a raw readonly-query envelope to the corpus expected shape."""
    if not isinstance(value, dict) or "rows" not in value:
        return value
    raw_rows = value.get("rows")
    if not isinstance(raw_rows, list):
        raise SkillEvalContractError(f"reference result malformed for {case.case_id}")
    authored = case.expected.value
    authored_table_mapping = (
        isinstance(authored, dict)
        and set(authored) >= {"columns", "rows"}
        and isinstance(authored.get("columns"), list)
        and isinstance(authored.get("rows"), list)
    )
    authored_table_rows = isinstance(authored, list) and all(
        isinstance(row, list) for row in authored
    )
    wants_rows = case.expected.mode == "rows" or authored_table_mapping or authored_table_rows
    if wants_rows and "columns" in value and all(isinstance(row, list) for row in raw_rows):
        normalized_columns = value.get("columns")
        if (
            not isinstance(normalized_columns, list)
            or not all(isinstance(column, str) for column in normalized_columns)
            or any(len(row) != len(normalized_columns) for row in raw_rows)
        ):
            raise SkillEvalContractError(f"reference columns invalid for {case.case_id}")
        normalized = {
            "columns": [column.casefold() for column in normalized_columns],
            "rows": raw_rows,
        }
        return raw_rows if authored_table_rows else normalized
    if not all(isinstance(row, dict) for row in raw_rows):
        raise SkillEvalContractError(f"reference result malformed for {case.case_id}")
    rows = [row for row in raw_rows if isinstance(row, dict)]
    if case.expected.mode == "scalar":
        if len(rows) != 1 or len(rows[0]) != 1:
            raise SkillEvalContractError(f"reference scalar shape invalid for {case.case_id}")
        return next(iter(rows[0].values()))
    if wants_rows:
        if authored_table_mapping:
            assert isinstance(authored, dict)
            raw_columns: object = authored["columns"]
        elif rows:
            raw_columns = list(rows[0])
        else:
            raw_columns = []
        if not isinstance(raw_columns, list) or not all(
            isinstance(column, str) for column in raw_columns
        ):
            raise SkillEvalContractError(f"reference columns invalid for {case.case_id}")
        columns = [column for column in raw_columns if isinstance(column, str)]
        projected: list[list[object]] = []
        for row in rows:
            folded = {str(key).casefold(): item for key, item in row.items()}
            try:
                projected.append([folded[column.casefold()] for column in columns])
            except KeyError as exc:
                raise SkillEvalContractError(
                    f"reference columns missing for {case.case_id}"
                ) from exc
        if authored_table_rows:
            return projected
        return {"columns": [column.casefold() for column in columns], "rows": projected}
    return value


def _canonical_comparable(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _expected_value(case: SkillCorpusCase, reference_values: Mapping[str, object]) -> object:
    if not case.expected.verify_live:
        return case.expected.value
    live = _normalised_reference(case, reference_values[case.case_id])
    authored = case.expected.value
    authored_is_table = (isinstance(authored, dict) and set(authored) >= {"columns", "rows"}) or (
        isinstance(authored, list) and all(isinstance(row, list) for row in authored)
    )
    if (
        authored is not None
        and (case.expected.mode in {"scalar", "rows"} or authored_is_table)
        and _canonical_comparable(authored) != _canonical_comparable(live)
    ):
        raise SkillEvalContractError(f"live reference drift for {case.case_id}")
    if case.expected.mode not in {"scalar", "rows"}:
        return {"expected_contract": authored, "live_reference": live}
    return live


def _scalar_in_text(value: object, text: str) -> bool:
    if value is None:
        return False
    folded = text.casefold()
    if isinstance(value, str):
        return value.casefold() in folded
    if type(value) is bool:
        return str(value).casefold() in folded
    if type(value) in {int, float}:
        expected = Decimal(str(value))
        for match in _NUMERIC_TOKEN.finditer(text):
            try:
                observed = Decimal(match.group("number").replace(",", ""))
            except InvalidOperation:
                continue
            if match.group("percent"):
                observed /= 100
            if observed == expected:
                return True
        return False
    return False


def _normalise_cell(value: object) -> str:
    if value is None:
        return ""
    if type(value) is bool:
        return str(value).casefold()
    if type(value) in {int, float, Decimal}:
        decimal = Decimal(str(value))
        return format(decimal.normalize(), "f")
    text = re.sub(r"\s+", " ", str(value).strip().strip("`*")).casefold()
    numeric = text.replace(",", "").strip("$£€ ")
    try:
        decimal = Decimal(numeric)
    except InvalidOperation:
        return text
    return format(decimal.normalize(), "f")


def _markdown_tables(candidate: str) -> list[tuple[list[str], list[list[str]]]]:
    tables: list[tuple[list[str], list[list[str]]]] = []
    block: list[list[str]] = []
    for line in [*candidate.splitlines(), ""]:
        if "|" in line:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) >= 2:
                block.append(cells)
                continue
        if len(block) >= 2 and all(_MARKDOWN_SEPARATOR.fullmatch(cell) for cell in block[1]):
            width = len(block[0])
            if all(len(row) == width for row in block[2:]):
                tables.append((block[0], block[2:]))
        block = []
    return tables


def _json_rows(candidate: str, columns: list[str]) -> list[list[list[object]]]:
    documents = [candidate.strip()]
    documents.extend(re.findall(r"```(?:json)?\s*(.*?)```", candidate, flags=re.DOTALL))
    outputs: list[list[list[object]]] = []
    for document in documents:
        try:
            payload = json.loads(document)
        except (json.JSONDecodeError, TypeError):
            continue
        raw_rows = payload.get("rows") if isinstance(payload, dict) else payload
        if not isinstance(raw_rows, list):
            continue
        rows: list[list[object]] = []
        valid = True
        for raw_row in raw_rows:
            if isinstance(raw_row, list):
                rows.append(list(raw_row))
            elif isinstance(raw_row, dict):
                if not columns:
                    valid = False
                    break
                folded = {str(key).casefold(): value for key, value in raw_row.items()}
                if not all(column.casefold() in folded for column in columns):
                    valid = False
                    break
                rows.append([folded[column.casefold()] for column in columns])
            else:
                valid = False
                break
        if valid:
            outputs.append(rows)
    return outputs


def result_value_matches(candidate: str, expected: object, *, ordered: bool) -> bool:
    """Compare an objective scalar/row result without flattening row identity."""
    expected_is_row_list = isinstance(expected, list) and all(
        isinstance(row, list) for row in expected
    )
    if expected_is_row_list:
        columns: list[str] = []
        assert isinstance(expected, list)
        raw_rows: list[list[object]] = [list(row) for row in expected if isinstance(row, list)]
    elif isinstance(expected, dict) and set(expected) >= {"columns", "rows"}:
        raw_columns = expected.get("columns")
        raw_table_rows = expected.get("rows")
        if (
            not isinstance(raw_columns, list)
            or not all(isinstance(column, str) for column in raw_columns)
            or not isinstance(raw_table_rows, list)
            or not all(isinstance(row, list) for row in raw_table_rows)
        ):
            return False
        columns = [column for column in raw_columns if isinstance(column, str)]
        raw_rows = [list(row) for row in raw_table_rows if isinstance(row, list)]
    else:
        return _candidate_contains_value(candidate, expected)
    if not raw_rows:
        folded = candidate.casefold()
        return any(marker in folded for marker in _EMPTY_RESULT_MARKERS)
    expected_rows = [tuple(_normalise_cell(cell) for cell in row) for row in raw_rows]
    candidates: list[list[list[object]]] = []
    for headers, rows in _markdown_tables(candidate):
        if columns:
            header_keys = [_header_key(header) for header in headers]
            column_keys = [_header_key(column) for column in columns]
            if len(set(header_keys)) != len(header_keys) or set(header_keys) != set(column_keys):
                continue
            positions = [header_keys.index(column) for column in column_keys]
            candidates.append([[row[position] for position in positions] for row in rows])
        else:
            candidates.append([[cell for cell in row] for row in rows])
    candidates.extend(_json_rows(candidate, columns))
    for candidate_rows in candidates:
        actual_rows = [tuple(_normalise_cell(cell) for cell in row) for row in candidate_rows]
        if ordered and actual_rows == expected_rows:
            return True
        if not ordered and Counter(actual_rows) == Counter(expected_rows):
            return True
    return False


def _header_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _candidate_contains_value(candidate: str, expected: object) -> bool:
    if isinstance(expected, dict):
        if set(expected) >= {"columns", "rows"} and isinstance(expected["rows"], list):
            return all(
                all(_candidate_contains_value(candidate, cell) for cell in row)
                for row in expected["rows"]
                if isinstance(row, list)
            )
        return all(_candidate_contains_value(candidate, value) for value in expected.values())
    if isinstance(expected, list):
        return all(_candidate_contains_value(candidate, value) for value in expected)
    return _scalar_in_text(expected, candidate)


class _SkillExpectationScorer:
    def __init__(
        self,
        *,
        corpus: SkillCorpus,
        target: _ConversationTarget,
        client: httpx.AsyncClient,
        target_url: str,
        token: str,
        reference_values: Mapping[str, object],
    ) -> None:
        self._corpus = corpus
        self._target = target
        self._client = client
        self._target_url = target_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._reference_values = reference_values
        self.shape_results: dict[str, bool] = {}

    async def score(
        self, case: EvalCase, output: CandidateOutput, *, request_id: str, tenant_id: str
    ) -> ScorerResult:
        del request_id, tenant_id
        source = self._corpus.case_by_id[case.id]
        observation = self._target.observations[case.id]
        if source.kind in _TRIGGER_KINDS:
            routed = read_skill_ids_from_dispatches(
                observation.dispatches,
                candidate_skill_ids=(self._corpus.manifest.skill_id,),
            )
            route_expected = expected_route(source, skill_id=self._corpus.manifest.skill_id)
            passed = (self._corpus.manifest.skill_id in routed) is route_expected
            return _assertion_result("skill_route", passed)

        expected_value = _expected_value(source, self._reference_values)
        if _routes_to_judge(source):
            return await self._judge(source, output.text, expected_value)
        return _assertion_result(
            "result_equivalence",
            result_value_matches(
                output.text,
                expected_value,
                ordered="order-insensitive" not in source.notes.casefold(),
            ),
        )

    async def _judge(self, case: SkillCorpusCase, candidate: str, expected: object) -> ScorerResult:
        criteria = [
            {
                "name": "value",
                "description": _criterion_description(
                    case=case,
                    expected=expected,
                    rubric_ref=self._corpus.manifest.judge.rubric_ref,
                    shape=False,
                ),
            }
        ]
        shape_case = (
            case.case_id in self._corpus.manifest.performance_conformance.non_gating_case_ids
        )
        if shape_case:
            criteria.append(
                {
                    "name": "performance_conformance",
                    "description": _criterion_description(
                        case=case,
                        expected=expected,
                        rubric_ref=self._corpus.manifest.judge.rubric_ref,
                        shape=True,
                    ),
                }
            )
        response = await self._client.post(
            f"{self._target_url}/api/v1/eval/judge",
            headers=self._headers,
            json={
                "candidate_output": candidate or " ",
                "candidate_input": case.question,
                "criteria": criteria,
            },
            follow_redirects=False,
        )
        _require_status(response, 200, operation="judge")
        try:
            verdict = JudgeVerdictResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise SkillEvalContractError("judge response shape invalid") from exc
        if verdict.model != self._corpus.manifest.judge.model_alias:
            raise SkillEvalContractError("judge model alias drift")
        by_name = {item.name: item for item in verdict.criteria_results}
        if set(by_name) != {item["name"] for item in criteria}:
            raise SkillEvalContractError("judge criteria response mismatch")
        # The ruled sh-104 class: shape is reported independently and cannot
        # make an otherwise-passing value verdict fail through the judge's
        # aggregate verdict.
        value_passed = by_name["value"].passed and (shape_case or verdict.verdict == "pass")
        if shape_case:
            self.shape_results[case.case_id] = by_name["performance_conformance"].passed
        return ScorerResult(
            scorer="judge",
            passed=value_passed,
            detail=tuple(
                CriterionDetail(name=item.name, passed=item.passed, critique=item.note)
                for item in verdict.criteria_results
            ),
            verdict=verdict.verdict,
            score=verdict.score,
            rationale=verdict.rationale,
        )


def _criterion_description(
    *, case: SkillCorpusCase, expected: object, rubric_ref: str, shape: bool
) -> str:
    if shape:
        text = (
            f"Apply performance-conformance rubric {rubric_ref}. Judge only the query-shape "
            f"requirements in this case note; this verdict is reported but non-gating. "
            f"Reference SQL: {case.reference_sql!r}. Note: {case.notes}"
        )
    else:
        text = (
            f"Apply value/outcome rubric {rubric_ref}. Required mode={case.expected.mode}; "
            f"expected={json.dumps(expected, ensure_ascii=True, sort_keys=True)}. "
            f"Reference SQL: {case.reference_sql!r}. Note: {case.notes}"
        )
    return text[:2_000]


def _assertion_result(name: str, passed: bool) -> ScorerResult:
    return ScorerResult(
        scorer="assertions",
        passed=passed,
        detail=(
            CriterionDetail(
                name=name,
                passed=passed,
                critique="" if passed else f"{name} did not match the corpus contract",
            ),
        ),
    )


async def run_skill_evaluation(
    corpus: SkillCorpus,
    *,
    target_url: str,
    token: str,
    agent_id: str,
    ablation_agent_id: str | None,
    reference_values: Mapping[str, object],
    http_client: httpx.AsyncClient | None = None,
) -> SkillGateReport:
    """Run the exact A-007 matrix through fresh conversation API sessions."""
    if corpus.manifest.judge.measured_kappa is None and any(
        _routes_to_judge(case) for case in corpus.cases
    ):
        raise SkillEvalRunRefused("skill_eval_judge_calibration_missing")
    if not token:
        raise SkillEvalContractError("bearer token is required")
    parsed_target = urlsplit(target_url)
    if (
        parsed_target.scheme not in {"http", "https"}
        or not parsed_target.netloc
        or parsed_target.username is not None
        or parsed_target.password is not None
        or parsed_target.path not in {"", "/"}
        or parsed_target.query
        or parsed_target.fragment
    ):
        raise SkillEvalContractError("target URL must be an absolute HTTP(S) origin")
    if not agent_id.strip():
        raise SkillEvalContractError("agent id is required")
    if corpus.manifest.ablation.enabled and (
        not ablation_agent_id or ablation_agent_id == agent_id
    ):
        raise SkillEvalContractError("a distinct ablation agent is required")
    required_references = set(required_reference_case_ids(corpus))
    if set(reference_values) != required_references:
        raise SkillEvalContractError("reference-results matrix mismatch")

    generic_corpus = build_eval_runner_corpus(corpus)
    owned_client = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=httpx.Timeout(360.0, connect=10.0, write=10.0, pool=10.0),
        follow_redirects=False,
    )
    verdicts: list[SkillCaseVerdict] = []
    variants: tuple[tuple[SkillEvalVariant, str], ...] = (
        (("with_skill", agent_id), ("without_skill", ablation_agent_id or ""))
        if corpus.manifest.ablation.enabled
        else (("with_skill", agent_id),)
    )
    try:
        for variant, variant_agent_id in variants:
            for repetition in range(1, corpus.manifest.n_reps + 1):
                target = _ConversationTarget(
                    client=client,
                    target_url=target_url,
                    token=token,
                    agent_id=variant_agent_id,
                )
                skill_scorer = _SkillExpectationScorer(
                    corpus=corpus,
                    target=target,
                    client=client,
                    target_url=target_url,
                    token=token,
                    reference_values=reference_values,
                )
                result = await EvalRunner().run(
                    generic_corpus,
                    target=target,
                    scorers=[AssertionScorer(), skill_scorer],
                    run_id=uuid.uuid4(),
                    chain_request_id=f"skill-eval-{uuid.uuid4().hex}",
                    tenant_id="skill-eval",
                )
                by_id = corpus.case_by_id
                verdicts.extend(
                    SkillCaseVerdict(
                        case_id=item.case_id,
                        kind=by_id[item.case_id].kind,
                        repetition=repetition,
                        variant=variant,
                        passed=item.passed,
                        errored=item.outcome == "errored",
                        shape_passed=skill_scorer.shape_results.get(item.case_id),
                    )
                    for item in result.cases
                )
    finally:
        if owned_client:
            await client.aclose()
    return compute_skill_gate(corpus, verdicts)


def skill_gate_report_payload(report: SkillGateReport) -> dict[str, object]:
    """Stable JSON-ready CLI projection; failures remain examiner-visible."""
    return {
        "skill_id": report.skill_id,
        "corpus_case_count": report.corpus_case_count,
        "n_reps": report.n_reps,
        "judge_model_alias": report.judge_model_alias,
        "judge_calibration_set_id": report.judge_calibration_set_id,
        "measured_judge_kappa": report.measured_judge_kappa,
        "minimum_judge_kappa": report.minimum_judge_kappa,
        "holdout_case_ids": list(report.holdout_case_ids),
        "passed": report.passed,
        "hard_zero_observed": report.hard_zero_observed,
        "trigger_accuracy": report.trigger_accuracy,
        "trigger_passed": report.trigger_passed,
        "accuracy": report.accuracy,
        "wrong_answer_rate": report.wrong_answer_rate,
        "golden_accuracy": report.golden_accuracy,
        "golden_all_correct": report.golden_all_correct,
        "golden_failure_case_ids": list(report.golden_failure_case_ids),
        "ablation_uplift": report.ablation_uplift,
        "ablation_passed": report.ablation_passed,
        "performance_conformance": dataclasses.asdict(report.performance_conformance),
        "class_metrics": [dataclasses.asdict(metric) for metric in report.class_metrics],
        "failure_case_ids": list(report.failure_case_ids),
    }
