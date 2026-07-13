# cognic-tool-example-minimal

Sprint-7A T15 **reference** tool pack — minimal-but-valid; inert by
design. The pack demonstrates the per-kind Wave-1 author lifecycle
for `kind = "tool"`:

```
uv lock                   # resolve, review, and commit in a copied repo
uv sync --frozen
uv run agentos sign --bundle .   # produces the seven attestations
uv run agentos validate .
uv run agentos test-harness .    # tools: PASS
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

For the full author guide (manifest blocks, Wave-1 governance
contracts, `cognic.tools` entry-point shape, supply-chain attestation
expectations), read `docs/HOW-TO-WRITE-A-PACK.md` in the cognic-
agentos repo.

## What this pack does

`ExampleMinimalTool._invoke({"message": x})` returns `{"echo": x}`.
The pack is intentionally inert; copy this directory and substitute
real tool behavior — the surrounding manifest + pyproject + per-kind
lifecycle will already be valid.

## Why a separate pack vs. the `cli/templates/tool/` scaffold

`cli/templates/tool/` is the Jinja-rendered scaffold consumed by
`agentos init-tool`; it carries `AUTHOR-FILL:` placeholders that trip
validator refusals until the author replaces them. This pack carries
**no** placeholders, so it gates the CI lifecycle — every committed
artifact matches the validator's accept-shape from the moment the
directory lands.
