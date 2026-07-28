"""{{ class_name }} — AUTHOR-FILL: short description of what this hook does.

The pack-author contract (Sprint-7A2 T2 SDK):

  - Override ``_invoke(context, payload)`` (NOT ``invoke``; the SDK's
    ``Hook.__init_subclass__`` rejects subclasses that override the
    public final method, mirroring the Tool / Skill pattern from
    Sprint-7A T2 R3 P2 #1 / R8 P2 #1).
  - Declare ``hook_id`` + ``phase`` ClassVars matching the manifest's
    ``[hooks].declarations`` block. The Sprint-7A2 T6 validator
    cross-checks manifest hook IDs against pyproject entry-point keys in
    both directions. Entry-point class metadata is deferred-load state; the
    runtime dispatcher checks it at first invocation and fails closed as a
    malformed result when it disagrees with the signed declaration.
  - Return a ``HookResult`` with one of four closed-enum decisions:
    ``"pass"`` (continue unchanged), ``"redact"`` / ``"mask"``
    (carry modified payload bytes forward), or ``"refuse"`` (with a
    non-empty hook-authored ``policy_reason``). Legacy DLP callers
    retain the established reason propagation; conversation callers
    suppress the string from evidence and expose only the kernel-owned
    ``conversation_hook_refused`` wire value.

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
    # [hooks].declarations[].hook_id field. DLP callers reference it
    # through dlp_*_hooks; conversation phases are selected phase-wide.
    hook_id: ClassVar[str] = "AUTHOR-FILL: e.g., redact_pii_in_input"

    # AUTHOR-FILL: phase MUST match the manifest. Sprint-7A2 T6
    # validator refuses input/output direction mismatches.
    # AUTHOR-FILL: dlp_pre | dlp_post | conversation_input |
    # conversation_output
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        """AUTHOR-FILL: implement the governance decision here.

        ``context`` carries hook_id / phase / pack_id (the CALLING
        pack) / tenant_id / request_id / trace_id /
        manifest_data_classes / manifest_purpose plus conversation
        correlation fields on conversation phases. DLP payloads are
        caller-defined bytes. Conversation payloads are the exact
        canonical JSON schema-v1 envelopes documented in
        ``docs/SDK-REFERENCE.md`` §8.4.1. Conversation phases are
        PASS/REFUSE-only in F-S2a: returning redact or mask fails closed until
        F-S3 lands transformation-aware examiner projection. Legacy DLP
        transforms return the complete caller-defined payload in
        ``redacted_payload``.

        Return one of:

          - ``HookResult(decision="pass", redacted_payload=None,
            policy_reason=None)`` — payload unchanged; dispatcher
            continues to the next hook.
          - ``HookResult(decision="redact" | "mask",
            redacted_payload=<modified bytes>, policy_reason=None)``
            — dispatcher replaces payload + continues for legacy DLP phases;
            conversation phases fail closed in F-S2a.
          - ``HookResult(decision="refuse", redacted_payload=None,
            policy_reason="<non-empty hook-authored reason>")`` —
            dispatcher short-circuits. Conversation callers suppress
            that reason and expose only ``conversation_hook_refused``.
        """
        raise NotImplementedError(
            "AUTHOR-FILL: implement {{ class_name }}._invoke"
        )
