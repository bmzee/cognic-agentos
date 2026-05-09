"""{{ class_name }} — AUTHOR-FILL: short description of what this hook does.

The pack-author contract (Sprint-7A2 T2 SDK):

  - Override ``_invoke(context, payload)`` (NOT ``invoke``; the SDK's
    ``Hook.__init_subclass__`` rejects subclasses that override the
    public final method, mirroring the Tool / Skill pattern from
    Sprint-7A T2 R3 P2 #1 / R8 P2 #1).
  - Declare ``hook_id`` + ``phase`` ClassVars matching the manifest's
    ``[hooks].declarations`` block. The Sprint-7A2 T6 validator
    cross-checks both directions; the runtime registry (T7) refuses
    admission if the wheel's entry-point class disagrees with the
    manifest declaration.
  - Return a ``HookResult`` with one of four closed-enum decisions:
    ``"pass"`` (continue unchanged), ``"redact"`` / ``"mask"``
    (carry modified payload bytes forward), or ``"refuse"`` (with a
    non-empty ``policy_reason`` so the dispatcher can route the
    refusal to the audit chain + the caller's refusal envelope).

  - Payload-contents-never-logged invariant (ADR-017 + Doctrine
    Lock E from the Sprint-7A2 plan-of-record): ``HookContext``
    deliberately omits payload bytes; the dispatcher passes
    ``payload`` separately. Pack-author hooks MUST NOT log payload
    bytes via any side channel (audit_metadata dict, print
    statements, exception messages, etc.). The runtime AST-walk
    regression (Sprint-7A2 T7) catches obvious leak patterns.
"""

from __future__ import annotations

from typing import ClassVar

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


class {{ class_name }}(Hook):
    """AUTHOR-FILL: docstring describing what governance check this hook performs."""

    # AUTHOR-FILL: hook_id matches the cognic-pack-manifest.toml
    # [hooks].declarations[].hook_id field + the calling pack's
    # [data_governance].dlp_pre_hooks / dlp_post_hooks reference.
    hook_id: ClassVar[str] = "AUTHOR-FILL: e.g., redact_pii_in_input"

    # AUTHOR-FILL: phase MUST match the manifest. Wave-1: dlp_pre |
    # dlp_post. Sprint-7A2 T6 validator refuses mismatches.
    phase: ClassVar[HookPhase] = "dlp_pre"  # AUTHOR-FILL: dlp_pre | dlp_post

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        """AUTHOR-FILL: implement the governance decision here.

        ``context`` carries hook_id / phase / pack_id (the CALLING
        pack) / tenant_id / request_id / trace_id /
        manifest_data_classes / manifest_purpose. ``payload`` is the
        opaque bytes the calling pack is about to receive (dlp_pre)
        or about to return (dlp_post).

        Return one of:

          - ``HookResult(decision="pass", redacted_payload=None,
            policy_reason=None)`` — payload unchanged; dispatcher
            continues to the next hook.
          - ``HookResult(decision="redact" | "mask",
            redacted_payload=<modified bytes>, policy_reason=None)``
            — dispatcher replaces payload + continues.
          - ``HookResult(decision="refuse", redacted_payload=None,
            policy_reason="<closed-enum reason>")`` — dispatcher
            short-circuits; calling-pack invocation refused.
        """
        raise NotImplementedError(
            "AUTHOR-FILL: implement {{ class_name }}._invoke"
        )
