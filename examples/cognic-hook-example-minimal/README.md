# cognic-hook-example-minimal

Sprint-7A2 T11 **reference** hook pack — minimal-but-valid; inert by
design. The pack demonstrates the per-kind Wave-1 author lifecycle
for `kind = "hook"`:

```
agentos sign --bundle .   # produces the seven attestations under attestations/
agentos validate .        # passes once attestations exist on disk
agentos test-harness .    # hooks: refused with `harness_unsupported_pack_kind`
agentos verify .
```

The committed reference pack is **static-only** — it does NOT ship
pre-generated attestations. `agentos validate .` declares
`supply_chain.attestation_paths` and refuses on a clean checkout
until `sign --bundle` populates the attestation set. Run sign first,
then validate; this matches the realistic author flow + the
lifecycle test.

The harness refusal is intentional. `cli/test_harness.py` Wave-1
narrows the dispatch table to `frozenset({"tool"})`; hook + skill +
agent harness expansion lands in a follow-up Sprint-7B task. **Sign
+ verify are kind-agnostic** — the lifecycle still runs end-to-end
through the supply-chain and trust-gate path.

For the full author guide read `docs/HOW-TO-WRITE-A-PACK.md` in the
cognic-agentos repo.

## What this pack does

`ExampleMinimalHook._invoke(context, payload)` returns
`HookResult(decision="pass", redacted_payload=None, policy_reason=None)`
unconditionally. Production hooks key their decision off `payload` +
the `HookContext` (`data_classes` / `purpose` / `tenant_id` / etc.)
and return `"redact"` / `"mask"` / `"refuse"` as the governance check
requires.

## What this pack does NOT ship

- **No `agent_cards/` directory** — hook packs do NOT ship an
  AgentCard JWS. The JWS arm is gated sign-side + verify-side, NOT
  validator-side: `cli/sign.py` skips JWS generation when
  `pack_kind != "agent"` and `cli/verify.py` skips Step 9 (JWS
  verification) under the same condition. Hook manifests simply
  omit `[identity].agent_card_jws_path` and the JWS arm is skipped
  end-to-end.
- **No `attestations/test-signing/` keypair** — only the agent
  reference pack ships the test-only signing halves used by the
  AgentCard JWS regen path; hook packs reuse the same keypair via
  the lifecycle-test fixture but never ship one of their own.
- **No `[a2a]` block** — hooks are not A2A-speaking. The
  orchestrator's `_FORBIDDEN_BLOCKS_BY_KIND` refuses hook packs
  declaring `[a2a]` with closed-enum `hook_pack_kind_constraint_violated`.
- **No `[mcp]` block** — hooks are not MCP-tool-shaped. Refused via
  the same gate.

## Why a separate pack vs. the `cli/templates/hook/` scaffold

`cli/templates/hook/` is the Jinja-rendered scaffold consumed by
`agentos init-hook`; it carries `AUTHOR-FILL:` placeholders. This
pack carries no placeholders, so it gates the CI lifecycle directly
via `tests/unit/cli/test_reference_packs_full_lifecycle_green.py::test_reference_hook_pack_full_lifecycle_green`.
