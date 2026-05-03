# policies/_default/sampling.rego
#
# Sprint-5 T6.2 — MCP sampling default-deny bundle.
#
# Per ADR-002 §"MCP Capabilities" + MCP-CONFORMANCE.md sampling
# row + ADR-015 §"Sampling default-deny": MCP server-initiated
# model sampling MUST be default-denied at admission. Operators
# override per-tenant by overriding this bundle (Sprint 13.5 Rego
# hot-reload).
#
# The four-condition gate (all four must hold for sampling to be
# allowed):
#
#   1. The pack manifest declares ``sampling_supported = true``
#      (the pack opts in to server-initiated sampling).
#   2. The tenant policy explicitly permits sampling for this pack
#      / pack class (operator-controlled; default-deny).
#   3. The cloud-policy permits the requested model tier (cloud-
#      vs-self-hosted boundary; consistency with ADR-007).
#   4. The model tier is consistent with the operator-set
#      ``allow_external_llm`` flag (no silent escape from the
#      self-hosted-first posture).
#
# The validator builds the input shape:
#   {
#     "pack": {"sampling_supported": <bool>},
#     "tenant": {"sampling_permitted": <bool>},
#     "cloud_policy": {
#       "tier_consistent": <bool>,
#       "allow_external_llm_consistent": <bool>
#     }
#   }
#
# The decision point is ``data.cognic.sampling.allow``.

package cognic.sampling

default allow = false

allow {
    input.pack.sampling_supported == true
    input.tenant.sampling_permitted == true
    input.cloud_policy.tier_consistent == true
    input.cloud_policy.allow_external_llm_consistent == true
}
