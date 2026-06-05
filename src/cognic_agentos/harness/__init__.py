"""AgentOS runtime composition root (Workstream #2 — Harness Injection).

OS runtime wiring ONLY — never Layer-C agent behaviour. ``build_runtime``
constructs the real kernel runtime (LLMGateway + governed-memory factory) from
Settings + the adapter pool; ``create_prod_app`` calls it from the lifespan (T8).
"""

from __future__ import annotations

from cognic_agentos.harness.runtime import Runtime, build_runtime

__all__ = ("Runtime", "build_runtime")
