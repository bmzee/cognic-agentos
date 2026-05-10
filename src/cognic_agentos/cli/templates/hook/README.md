# {{ pack_id }}

AUTHOR-FILL: short description of what this hook pack does.

This is a Cognic AgentOS **hook pack** — a deterministic governance
extension registered under the `cognic.hooks` entry-point group per
ADR-017 + the Sprint-7A2 hook taxonomy. Hook packs are NOT Layer C
agent behavior; they run on the runtime DLP / governance pipeline
to gate inputs / outputs of tool / skill / agent packs.

## Wave-1 author lifecycle

The canonical workflow is **sign-before-validate** (per the Sprint-7A
T15 + T16 static-only-committed-state doctrine: `agentos validate`
checks that every declared `supply_chain.attestation_paths` file
exists on disk; sign produces them, then validate clears):

```
python -m build --wheel        # or `uv build`
agentos sign --bundle .         # produces the seven attestations
agentos validate .              # passes once attestations exist
agentos verify .                # offline trust-gate dry-run
```

Hook packs do NOT participate in `agentos test-harness` Wave-1; the
harness is narrowed to `kind = "tool"` (per T13/R31). Hook dispatch
dry-runs land in a follow-up sprint alongside the skill + agent
harness expansion.

## What this pack ships

- `cognic-pack-manifest.toml` — Wave-1 manifest with the new
  `[hooks]` block declaring this pack's hook IDs + phases +
  ordering classes + timeouts + fail-policy.
- `pyproject.toml` — `[project.entry-points."cognic.hooks"]` lists
  one entry per declared hook ID.
- `src/{{ module_name }}/hook.py` — the `{{ class_name }}` subclass of
  `cognic_agentos.sdk.hook.Hook`, overriding `_invoke(context,
  payload)`.
- `tests/test_hook.py` — smoke tests; AUTHOR-FILL: extend with real
  coverage of every decision branch (pass / redact / mask / refuse).

## What this pack does NOT ship

- **No `agent_cards/` directory** — hook packs do NOT ship an
  AgentCard JWS. The Sprint-7A2 T6 validator refuses
  `kind = "hook"` packs that declare `agent_card_jws_path`.
- **No `[a2a]` block** — hooks are not A2A-speaking.
- **No `[mcp]` block** — hooks are not MCP-tool-shaped.

## Pre-publish checklist

- [ ] Replace every `AUTHOR-FILL:` placeholder in
      `cognic-pack-manifest.toml` + `pyproject.toml` +
      `src/{{ module_name }}/hook.py`.
- [ ] Implement `{{ class_name }}._invoke()` — return one of the four
      `HookResult` decisions (pass / redact / mask / refuse).
- [ ] Replace the skipped smoke test with real coverage of every
      decision branch.
- [ ] Run `python -m build --wheel`.
- [ ] Run `agentos sign --bundle .` → populates `attestations/`.
- [ ] Run `agentos validate .` → expect green.
- [ ] Run `agentos verify .` → expect exit 0.

For the full author tutorial read `docs/HOW-TO-WRITE-A-PACK.md` in
the cognic-agentos repo.
