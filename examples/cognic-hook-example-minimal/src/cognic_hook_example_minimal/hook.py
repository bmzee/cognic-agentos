"""Sprint-7A2 T11 reference hook — inert deterministic decision.

Returns ``HookResult(decision="pass")`` unconditionally. Lets pack
authors copy a working ``Hook`` subclass that already passes the
SDK's contract-validation seam (``_invoke`` override; ``hook_id`` +
``phase`` ClassVars matching the manifest).

Per Doctrine D from the Sprint-7A T15 closeout (carried into 7A2 T11),
the pack is **inert** — the hook always passes through. NOT a model
for production hook implementation; production hooks key their
decision off the payload + the ``HookContext`` (data_classes /
purpose / tenant_id / etc.) and return ``"redact"`` / ``"mask"`` /
``"refuse"`` as the governance check requires.

Payload-contents-never-logged invariant (ADR-017 + Doctrine Lock E):
this hook receives ``payload: bytes`` but never logs / stores /
exfiltrates them. The runtime AST-walk regression at
``tests/architecture/test_hook_payload_never_logged.py`` (Sprint-7A2
T7) catches obvious leak patterns; the inert reference body honors
the invariant by not touching ``payload`` at all.
"""

from __future__ import annotations

from typing import ClassVar

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


class ExampleMinimalHook(Hook):
    """Inert deterministic hook — Wave-1 reference implementation."""

    hook_id: ClassVar[str] = "example_minimal"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        # Inert: payload unchanged; dispatcher continues to the next
        # hook (or to pack code for the final dlp_pre hook). No
        # payload bytes are read, logged, or stored — preserves the
        # ADR-017 + Doctrine Lock E invariant by construction.
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)
