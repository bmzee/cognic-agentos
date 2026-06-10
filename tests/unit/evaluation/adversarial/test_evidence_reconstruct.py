from __future__ import annotations

import uuid
from typing import Any

from cognic_agentos.evaluation.adversarial.evidence import _eval_run_from_get_run
from cognic_agentos.evaluation.types import EvalRunResult


def _get_run_mapping(run_id: uuid.UUID) -> dict[str, Any]:
    return {
        "run": {
            "run_id": run_id,
            "chain_request_id": "r",
            "corpus_id": "adv",
            "corpus_digest": "d",
            "target_kind": "gateway",
            "tier": "tier1",
            "total": 1,
            "passed": 1,
            "failed": 0,
            "errored": 0,
            "latency_p50_ms": 1,
            "latency_p95_ms": 1,
        },
        "cases": [
            {
                "case_id": "a::none",
                "passed": True,
                "outcome": "succeeded",
                "latency_ms": 1,
                "model": "m",
                "input_digest": "i",
                "output_digest": "o",
                "candidate_output_text": None,
            }
        ],
    }


def test_eval_run_from_get_run_reconstructs_fields_compute_replay_diff_reads() -> None:
    run_id = uuid.uuid4()
    result = _eval_run_from_get_run(_get_run_mapping(run_id))
    assert isinstance(result, EvalRunResult)
    assert result.run_id == run_id
    assert result.corpus_digest == "d"
    assert result.tier == "tier1"
    assert len(result.cases) == 1
    c = result.cases[0]
    assert (c.case_id, c.passed, c.outcome, c.output_digest, c.model) == (
        "a::none",
        True,
        "succeeded",
        "o",
        "m",
    )
