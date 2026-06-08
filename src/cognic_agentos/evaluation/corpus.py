"""Sprint 12 corpus contract + fail-closed loader (ADR-010 amendment) — CC.

The strict Pydantic models (``extra="forbid"``) ARE the single source of truth
for corpus validity: ``load_corpus(path)`` is the directory/YAML wrapper used by
the CLI ``--dry-run``; ``validate_corpus_payload(dict)`` validates an already-
parsed inline body (the portal path) against the SAME models. A corpus valid for
one is valid for the other — no second validator to drift.
"""

from __future__ import annotations

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


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=200)
    case_kind: Literal["completion"]
    messages: list[_Message] = Field(min_length=1)
    assertions: AssertionsBlock | None = None
    judge: JudgeBlock | None = None

    @model_validator(mode="after")
    def _declares_a_scorer(self) -> EvalCase:
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
        if "messages" in loc:
            return "corpus_case_messages_invalid"
        msg = str(err.get("msg", ""))
        if "neither assertions nor judge" in msg:
            return "corpus_case_no_scorer"
    return "corpus_case_messages_invalid"


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
