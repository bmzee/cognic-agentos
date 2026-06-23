# cognic-tool-search (Proof 1a example pack)

A minimal **real** MCP tool pack used by the Proof 1a end-to-end pack-governance
loop (`tests/integration/pack_loop/`). It exposes one deterministic tool,
`search_policy_docs(query)`, over a small bundled static corpus - no network, no
LLM - so the proof fails only on AgentOS integration, never on a provider.

This pack lives in-tree but is **not** part of the AgentOS wheel
(`packages = ["src/cognic_agentos"]`); it is built into its own wheel, signed
with `agentos sign`, and installed as an external pack. See
`docs/superpowers/specs/2026-06-21-pack-loop-proof-1a-design.md`.
