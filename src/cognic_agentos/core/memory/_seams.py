"""Sprint 11.5a — memory kill-switch seam (consumer-owned Protocol + fail-loud
sentinel). The real Redis-backed memory.write_freeze lands in Sprint 11.5b at
core/emergency/kill_switches.py. core/ stop-rule per AGENTS.md (Memory
governance enforcement, ADR-019). Mirrors core/scheduler/_seams.py.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class MemoryKillSwitchInterrogator(Protocol):
    """Per-tenant memory.write-freeze probe. Required injected seam — the
    MemoryAPI write path calls is_write_frozen() before every durable write.
    Sprint 11.5b implements the real Redis-backed version at
    core/emergency/kill_switches.py."""

    async def is_write_frozen(self, *, tenant_id: str) -> bool: ...


class _NullMemoryKillSwitchInterrogator:
    """Fail-loud sentinel. Production has NO permissive default — a wiring miss
    surfaces immediately rather than silently allowing writes during a
    compliance freeze. Sprint 11.5b supplies the real Redis implementation;
    tests inject an inactive conformer."""

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        raise NotImplementedError(
            "MemoryKillSwitchInterrogator not wired. Sprint 11.5b "
            "(core/emergency/kill_switches.py) supplies the real Redis "
            "implementation; pre-11.5b deployments must inject a structural "
            "conformer at MemoryAPI construction."
        )
