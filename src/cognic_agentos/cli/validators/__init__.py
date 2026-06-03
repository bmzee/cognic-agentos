"""Sprint-7A T7-T12 — `cli/validators/` per-concern validators.

The :mod:`cognic_agentos.cli.validate` orchestrator dispatches to one
file per concern (identity / a2a / mcp / data_governance / risk_tier /
supply_chain) so future sprints can extend each independently. Every
validator exports a single function with the canonical signature::

    def validate(
        data: dict[str, Any],
        pack_path: pathlib.Path,
    ) -> list[cognic_agentos.cli.ValidatorFinding]: ...

Returning the empty list means "no findings — this concern's checks
all passed". Findings carry the closed-enum
:class:`~cognic_agentos.cli.ValidatorReason` literal as ``reason``;
adding a new reason requires updating the literal +
``_VALIDATOR_REASON_OWNERSHIP`` mapping in :mod:`cognic_agentos.cli`.

T6 ships every validator as a fail-loud stub returning ``[]``.
T7-T12 each replace one stub body with the real per-concern logic
without touching :mod:`cognic_agentos.cli.validate`.
"""

from __future__ import annotations

from cognic_agentos.cli.validators import (
    a2a,
    data_governance,
    hooks,
    identity,
    learning_surface,
    mcp,
    risk_tier,
    supply_chain,
)

__all__ = [
    "a2a",
    "data_governance",
    "hooks",
    "identity",
    "learning_surface",
    "mcp",
    "risk_tier",
    "supply_chain",
]
