"""Deterministic in-memory search over the bundled static policy-doc corpus.

No network, no LLM (a tool pack must not embed an LLM — three-pool rule). The
corpus ships as package data; load_corpus() reads it via importlib.resources so
it resolves the same way inside an installed wheel.
"""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

_SNIPPET_LEN = 160


def load_corpus() -> list[dict[str, Any]]:
    raw = (
        resources.files("cognic_tool_search")
        .joinpath("corpus/policy_docs.json")
        .read_text(encoding="utf-8")
    )
    docs: list[dict[str, Any]] = json.loads(raw)
    return docs


def search(corpus: list[dict[str, Any]], query: str) -> list[dict[str, str]]:
    """Case-insensitive substring match over title+body. Deterministic: preserves
    corpus order; returns a stable {doc_id, title, snippet} shape."""
    q = query.strip().lower()
    if not q:
        return []
    hits: list[dict[str, str]] = []
    for doc in corpus:
        haystack = f"{doc['title']} {doc['body']}".lower()
        if q in haystack:
            body = doc["body"]
            idx = body.lower().find(q)
            start = max(0, idx - 20) if idx >= 0 else 0
            snippet = body[start : start + _SNIPPET_LEN]
            hits.append({"doc_id": doc["doc_id"], "title": doc["title"], "snippet": snippet})
    return hits
