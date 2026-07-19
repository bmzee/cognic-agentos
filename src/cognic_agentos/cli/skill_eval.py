"""Thin CLI adapter for the A-007 conversations-based skill evaluator."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.evaluation.skill_corpus import SkillCorpus


def _load_reference_results(path: Path | None, *, corpus: SkillCorpus) -> dict[str, object]:
    if path is None:
        return {}
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-standard JSON constant {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("reference-results file is unreadable") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "reference",
        "results",
    }:
        raise ValueError("reference-results file has an invalid envelope")
    reference = payload.get("reference")
    expected_reference = corpus.manifest.reference.model_dump(mode="json")
    if (
        payload.get("schema_version") != 1
        or not isinstance(reference, dict)
        or reference != expected_reference
    ):
        raise ValueError("reference-results provenance does not match the skill manifest")
    results = payload.get("results")
    if not isinstance(results, dict) or not all(isinstance(key, str) for key in results):
        raise ValueError("reference-results matrix must be a JSON object")
    required = {
        case.case_id
        for case in corpus.cases
        if case.expected.verify_live and case.reference_sql is not None
    }
    if set(results) != required:
        raise ValueError("reference-results matrix does not match the skill corpus")
    return results


def run_skill_eval_cli(
    *,
    pack: Path,
    target: str,
    token: str,
    agent_id: str,
    ablation_agent_id: str | None,
    reference_results: Path | None,
) -> tuple[int, str]:
    """Return ``(exit_code, output)`` without ever rendering the bearer token."""
    from cognic_agentos.evaluation.skill_corpus import SkillCorpusLoadError, load_skill_corpus
    from cognic_agentos.evaluation.skill_eval import (
        SkillEvalContractError,
        find_skill_contamination,
        run_skill_evaluation,
        skill_gate_report_payload,
    )

    try:
        corpus = load_skill_corpus(pack)
        references = _load_reference_results(reference_results, corpus=corpus)
        contaminated = find_skill_contamination(
            pack,
            corpus,
            reference_values=references or None,
        )
        if contaminated:
            raise SkillEvalContractError(
                f"SKILL.md contains golden answer text for cases {','.join(contaminated)}"
            )
        report = asyncio.run(
            run_skill_evaluation(
                corpus,
                target_url=target,
                token=token,
                agent_id=agent_id,
                ablation_agent_id=ablation_agent_id,
                reference_values=references,
            )
        )
    except SkillCorpusLoadError as exc:
        return (2, f"skill-eval: corpus invalid: {exc.reason}")
    except (SkillEvalContractError, ValueError) as exc:
        return (2, f"skill-eval: {exc}")
    output = json.dumps(skill_gate_report_payload(report), sort_keys=True, separators=(",", ":"))
    return (0 if report.passed else 1, output)
