# cognic-skill-example-minimal

Sprint-7A T15 **reference** skill pack — minimal-but-valid; inert by
design. The pack demonstrates the per-kind Wave-1 author lifecycle
for `kind = "skill"`:

```
uv lock                   # resolve, review, and commit in a copied repo
uv sync --frozen
uv run agentos sign --bundle .
uv run agentos validate .
uv run agentos test-harness .    # skills: PASS
uv run agentos verify .
```

The committed reference pack is **static-only** — it does NOT ship
pre-generated attestations or resolver output. Its unit lifecycle injects a
synthetic lock only into a temporary clone. A copied/released repository must
resolve, review, and commit its own `uv.lock`; signing refuses without it.
`agentos validate .` declares
`supply_chain.attestation_paths` and refuses on a clean checkout
until `sign --bundle` populates the attestation set. Run sign first,
then validate; this matches the realistic author flow + the
lifecycle test.

The harness dispatches through the public `Skill.execute()` seam. **Sign +
verify are kind-agnostic** — the lifecycle runs end-to-end through the
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
