"""Sprint-7A T14 fixture pack package init.

The ``cognic_agent_sign_target`` package is the importable Python
module surface the T14 sign + verify orchestrators reference. Inert
by design — the pack ships only to be exercised by the sign-bundle
orchestrator + the offline trust-gate verifier in the unit lane.
"""

from __future__ import annotations

from cognic_agent_sign_target.agent import SignTargetAgent

__all__ = ["SignTargetAgent"]
