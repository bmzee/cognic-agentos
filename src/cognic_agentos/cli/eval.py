"""`agentos eval-bulk` — thin portal client + local --dry-run (ADR-010)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_and_summarise(corpus_path: Path) -> dict[str, Any]:
    """Strict-load the corpus; return a plan summary. Raises CorpusLoadError."""
    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    return {
        "corpus_id": corpus.corpus_id,
        "case_count": len(corpus.cases),
        "cases": [
            {
                "id": c.id,
                "scorers": [
                    s
                    for s, present in (
                        ("assertions", c.assertions is not None),
                        ("judge", c.judge is not None),
                    )
                    if present
                ],
            }
            for c in corpus.cases
        ],
    }


def post_bulk_run(corpus_path: Path, *, url: str, token: str) -> dict[str, Any]:
    """POST the loaded corpus to the portal bulk-run endpoint; return the JSON body."""
    import httpx

    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    resp = httpx.post(
        f"{url.rstrip('/')}/api/v1/eval/bulk-run",
        headers={"Authorization": f"Bearer {token}"},
        json={"corpus": corpus.model_dump(), "target": "gateway", "persist_raw_output": False},
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def replay_dry_run_summary(corpus_path: Path, baseline: str) -> dict[str, Any]:
    """Validate corpus + baseline-UUID SHAPE only (no network).

    Raises CorpusLoadError / ValueError.
    """
    import uuid as _uuid

    from cognic_agentos.evaluation.corpus import load_corpus

    _uuid.UUID(baseline)  # ValueError on malformed
    corpus = load_corpus(corpus_path)
    return {"corpus_id": corpus.corpus_id, "case_count": len(corpus.cases), "baseline": baseline}


def post_replay(corpus_path: Path, *, baseline: str, url: str, token: str) -> dict[str, Any]:
    """POST the loaded corpus to the portal replay endpoint; return the JSON body."""
    import httpx

    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    resp = httpx.post(
        f"{url.rstrip('/')}/api/v1/eval/replay",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "corpus": corpus.model_dump(),
            "baseline_run_id": baseline,
            "persist_raw_output": False,
        },
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def adversarial_dry_run_summary(corpus_path: Path) -> dict[str, Any]:
    """Validate the adversarial corpus SHAPE only (no network).

    Raises ``CorpusLoadError`` on load/shape failure, and
    ``ValueError("corpus_not_all_adversarial")`` when any case is non-adversarial —
    mirroring the route's adversarial-only preflight so ``--dry-run`` cannot
    green-light a corpus the portal would reject with ``400
    corpus_not_all_adversarial`` (``corpus_not_all_adversarial`` is a route-level
    reason, NOT a ``CorpusLoadReason`` — a mixed corpus loads cleanly).
    """
    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    if any(c.case_kind != "adversarial" for c in corpus.cases):
        raise ValueError("corpus_not_all_adversarial")
    return {"corpus_id": corpus.corpus_id, "case_count": len(corpus.cases)}


def post_adversarial(corpus_path: Path, *, url: str, token: str) -> dict[str, Any]:
    """POST the loaded corpus to the portal adversarial-run endpoint; return the JSON body."""
    import httpx

    from cognic_agentos.evaluation.corpus import load_corpus

    corpus = load_corpus(corpus_path)
    resp = httpx.post(
        f"{url.rstrip('/')}/api/v1/eval/adversarial-run",
        headers={"Authorization": f"Bearer {token}"},
        json={"corpus": corpus.model_dump(), "persist_raw_output": False},
        timeout=120.0,
    )
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def render(summary: dict[str, Any], *, json_output: bool) -> str:
    if json_output:
        return json.dumps(summary, indent=2, sort_keys=True)
    lines = [
        f"corpus: {summary.get('corpus_id')}",
        f"cases: {summary.get('case_count', summary.get('total'))}",
    ]
    return "\n".join(lines)
