"""Sprint 12 corpus contract + fail-closed loader (ADR-010 amendment) — CC.

The strict Pydantic models (``extra="forbid"``) ARE the single source of truth
for corpus validity: ``load_corpus(path)`` is the directory/YAML wrapper used by
the CLI ``--dry-run``; ``validate_corpus_payload(dict)`` validates an already-
parsed inline body (the portal path) against the SAME models. A corpus valid for
one is valid for the other — no second validator to drift.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

_SUPPORTED_SCHEMA_VERSION = 1

CorpusLoadReason = Literal[
    "corpus_no_documents",
    "corpus_unparseable_yaml",
    "corpus_unknown_key",
    "corpus_schema_version_unsupported",
    "corpus_duplicate_case_id",
    "corpus_case_no_scorer",
    "corpus_case_kind_unsupported",
    "corpus_case_messages_invalid",
    "corpus_adversarial_block_missing",
    "corpus_adversarial_block_forbidden",
    "corpus_adversarial_category_not_runnable",
    "corpus_adversarial_forbidden_markers_empty",
]


class CorpusLoadError(Exception):
    """Fail-closed corpus rejection carrying a closed-enum ``reason``."""

    def __init__(self, reason: CorpusLoadReason, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason: CorpusLoadReason = reason
        self.detail = detail


class _Message(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=50_000)


class AssertionsBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    contains: list[str] = Field(default_factory=list)
    not_contains: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    json_path: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _at_least_one_clause(self) -> AssertionsBlock:
        if not (self.contains or self.not_contains or self.regex or self.json_path):
            raise ValueError("assertions block declares no clauses")
        return self


class JudgeCriterionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    weight: float | None = None  # recorded; non-gating in Sprint 12


class JudgeBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rubric: str | None = Field(default=None, max_length=2_000)
    criteria: list[JudgeCriterionSpec] = Field(min_length=1, max_length=20)


# --- ADR-011 Sprint-13b adversarial vocabulary -------------------------------

AttackCategory = Literal[
    "direct_prompt_injection",
    "jailbreak_persona_shift",
    "authority_misrepresentation",
    "indirect_prompt_injection",
    "multi_turn_social_engineering",
    "pii_extraction",
    "citation_poisoning",
    "tool_call_hijacking",
    "subagent_privilege_escalation",
    "cost_dos",
]

MutationStrategy = Literal["none", "unicode_confusables", "encoding", "paraphrase"]

#: The 3 categories runnable against a single-shot governed completion (the only
#: OS-only SUT). The other 7 are deferred with explicit reasons — examiner-visible
#: but never loadable into a corpus (they cannot reach the runner).
_RUNNABLE_CATEGORIES: frozenset[AttackCategory] = frozenset(
    {"direct_prompt_injection", "jailbreak_persona_shift", "authority_misrepresentation"}
)

_DEFERRED_CATEGORIES: dict[AttackCategory, str] = {
    "indirect_prompt_injection": "no_retrieval_target",
    "multi_turn_social_engineering": "no_multi_turn_target",
    "pii_extraction": "no_memory_context_target",
    "citation_poisoning": "no_citation_target",
    "tool_call_hijacking": "no_mcp_tool_target",
    "subagent_privilege_escalation": "no_subagent_target",
    "cost_dos": "cost_semantics_deferred",
}


class AdversarialBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    attack_category: AttackCategory
    forbidden_markers: list[str] = Field(min_length=1)
    severity: Literal["standard", "high"]
    mutation_strategies: list[MutationStrategy] = Field(min_length=1)

    @model_validator(mode="after")
    def _category_runnable(self) -> AdversarialBlock:
        if self.attack_category not in _RUNNABLE_CATEGORIES:
            raise ValueError(f"attack_category {self.attack_category} is deferred / not runnable")
        return self


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=200)
    case_kind: Literal["completion", "adversarial"]
    messages: list[_Message] = Field(min_length=1)
    assertions: AssertionsBlock | None = None
    judge: JudgeBlock | None = None
    adversarial: AdversarialBlock | None = None

    @model_validator(mode="after")
    def _case_kind_block_consistency(self) -> EvalCase:
        if self.case_kind == "adversarial":
            if self.adversarial is None:
                raise ValueError("adversarial case declares no adversarial block")
        else:  # completion
            if self.adversarial is not None:
                raise ValueError("completion case must not declare an adversarial block")
            if self.assertions is None and self.judge is None:
                raise ValueError("case declares neither assertions nor judge")
        return self


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int
    corpus_id: str = Field(min_length=1, max_length=200)
    description: str | None = None
    cases: list[EvalCase] = Field(min_length=1)


def _reason_for_validation_error(exc: ValidationError) -> CorpusLoadReason:
    """Map a pydantic ValidationError to the closed CorpusLoadReason taxonomy."""
    for err in exc.errors():
        etype = err.get("type", "")
        loc = err.get("loc", ())
        if etype == "extra_forbidden":
            return "corpus_unknown_key"
        if "case_kind" in loc:
            return "corpus_case_kind_unsupported"
        if "forbidden_markers" in loc:
            return "corpus_adversarial_forbidden_markers_empty"
        if "messages" in loc:
            return "corpus_case_messages_invalid"
        msg = str(err.get("msg", ""))
        if "no adversarial block" in msg:
            return "corpus_adversarial_block_missing"
        if "must not declare an adversarial block" in msg:
            return "corpus_adversarial_block_forbidden"
        if "deferred / not runnable" in msg:
            return "corpus_adversarial_category_not_runnable"
        if "neither assertions nor judge" in msg:
            return "corpus_case_no_scorer"
    return "corpus_case_messages_invalid"


def corpus_digest(corpus: Corpus) -> str:
    """Canonical digest of a corpus — sha256 of its Pydantic JSON serialization.

    BYTE-IDENTICAL to the Sprint-12 inline runner formula
    ``sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()`` — the
    replay pre-run guard compares this against the stored baseline's
    ``eval_runs.corpus_digest``, so any drift would falsely reject every
    existing baseline. Pinned by tests/unit/evaluation/test_corpus_digest.py.
    """
    return hashlib.sha256(corpus.model_dump_json().encode("utf-8")).hexdigest()


def validate_corpus_payload(payload: dict[str, Any]) -> Corpus:
    """Validate an already-parsed corpus dict against the strict models."""
    if payload.get("schema_version") != _SUPPORTED_SCHEMA_VERSION:
        raise CorpusLoadError(
            "corpus_schema_version_unsupported",
            f"expected {_SUPPORTED_SCHEMA_VERSION}, got {payload.get('schema_version')!r}",
        )
    try:
        return Corpus.model_validate(payload)
    except ValidationError as exc:
        raise CorpusLoadError(_reason_for_validation_error(exc), str(exc)) from exc


def load_corpus(path: Path) -> Corpus:
    """Load + merge every ``*.yaml``/``*.yml`` under ``path`` into one Corpus.

    Deterministic sorted file order; duplicate ``case.id`` across files fails
    closed; the merged corpus inherits the FIRST document's corpus_id/description.
    """
    files = sorted(p for p in path.glob("*.y*ml") if p.suffix in {".yaml", ".yml"})
    if not files:
        raise CorpusLoadError("corpus_no_documents", str(path))

    merged_cases: list[dict[str, Any]] = []
    head: dict[str, Any] | None = None
    seen_ids: set[str] = set()
    for f in files:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise CorpusLoadError("corpus_unparseable_yaml", f"{f.name}: {exc}") from exc
        if not isinstance(doc, dict):
            raise CorpusLoadError("corpus_unparseable_yaml", f"{f.name}: not a mapping")
        # Validate each document strictly first (catches unknown keys / kinds).
        corpus_doc = validate_corpus_payload(doc)
        if head is None:
            head = {"corpus_id": corpus_doc.corpus_id, "description": corpus_doc.description}
        for case in corpus_doc.cases:
            if case.id in seen_ids:
                raise CorpusLoadError("corpus_duplicate_case_id", case.id)
            seen_ids.add(case.id)
            merged_cases.append(case.model_dump())

    assert head is not None  # files non-empty ⇒ head set
    return validate_corpus_payload(
        {
            "schema_version": _SUPPORTED_SCHEMA_VERSION,
            "corpus_id": head["corpus_id"],
            "description": head["description"],
            "cases": merged_cases,
        }
    )
