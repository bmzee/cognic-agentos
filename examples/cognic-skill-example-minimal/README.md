# cognic-skill-example-minimal

Sprint-7A T15 **reference** skill pack — minimal-but-valid; inert by
design. The pack demonstrates the per-kind Wave-1 author lifecycle
for `kind = "skill"`:

```
agentos sign --bundle .   # produces the seven attestations under attestations/
agentos validate .        # passes once attestations exist on disk
agentos test-harness .    # skills: refused with `harness_unsupported_pack_kind`
agentos verify .
```

The committed reference pack is **static-only** — it does NOT ship
pre-generated attestations. `agentos validate .` declares
`supply_chain.attestation_paths` and refuses on a clean checkout
until `sign --bundle` populates the attestation set. Run sign first,
then validate; this matches the realistic author flow + the
lifecycle test.

The harness refusal is intentional. `cli/test_harness.py` Wave-1
narrows the dispatch table to `frozenset({"tool"})`; skill + agent
harness expansion lands in a follow-up Sprint-7B task. **Sign + verify
are kind-agnostic** — the lifecycle still runs end-to-end through the
supply-chain and trust-gate path.

For the full author guide read `docs/HOW-TO-WRITE-A-PACK.md` in the
cognic-agentos repo.

## What this pack does

`ExampleMinimalSkill.execute({"message": x})` resolves the
`example_minimal` tool via the bound `ToolRegistry`, calls
`tool.invoke(message=x)`, and returns `{"composed": {"echo": x}}`.

## Why a separate pack vs. the `cli/templates/skill/` scaffold

`cli/templates/skill/` is the Jinja-rendered scaffold consumed by
`agentos init-skill`; it carries `AUTHOR-FILL:` placeholders. This
pack carries no placeholders, so it gates the CI lifecycle directly.
