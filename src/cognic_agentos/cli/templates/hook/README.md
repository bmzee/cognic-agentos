# {{ pack_id }}

AUTHOR-FILL: short description of what this hook pack does.

This is a Cognic AgentOS **hook pack** — a deterministic governance
extension registered under the `cognic.hooks` entry-point group per
ADR-017 + the Sprint-7A2 hook taxonomy. Hook packs are NOT Layer C
agent behavior; they run on the runtime DLP / governance pipeline
to gate DLP and conversation input/output phases.

## Wave-1 author lifecycle

The canonical workflow is **sign-before-validate** (per the Sprint-7A
T15 + T16 static-only-committed-state doctrine: `agentos validate`
checks that every declared `supply_chain.attestation_paths` file
exists on disk; sign produces them, then validate clears):

```
uv lock                        # review + commit uv.lock
uv lock --check
uv sync --frozen --extra dev
uv build --wheel
uv run agentos sign --bundle .  # produces the seven attestations
uv run agentos validate .       # passes once attestations exist
uv run agentos test-harness .   # Hook.invoke(context, payload) dry-run
uv run agentos verify .         # offline trust-gate dry-run
```

Hook packs participate in `agentos test-harness` through the public
`Hook.invoke(context, payload)` seam; the SDK's context, payload, and result
validation phases all run before the dry-run can pass. Conversation-phase
authors must also follow the exact canonical JSON schema-v1 envelope in
`docs/SDK-REFERENCE.md` §8.4.1. In F-S2a those phases are PASS/REFUSE-only:
returning redact or mask fails closed until F-S3 lands transformation-aware
examiner projection. Legacy `dlp_pre` / `dlp_post` hooks retain transformation
support and return a complete envelope rather than a bare replacement string.

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
      `HookResult` decisions (pass / redact / mask / refuse), observing that
      conversation phases admit only pass/refuse in F-S2a.
- [ ] Replace the skipped smoke test with real coverage of every
      decision branch.
- [ ] Commit `uv.lock`; run `uv lock --check` +
      `uv sync --frozen --extra dev`.
- [ ] Run `uv build --wheel`.
- [ ] Run `uv run agentos sign --bundle .` → populates `attestations/`.
- [ ] Run `uv run agentos validate .` → expect green.
- [ ] Run `uv run agentos test-harness .` → expect green.
- [ ] Run `uv run agentos verify .` → expect exit 0.

For the full author tutorial read `docs/HOW-TO-WRITE-A-PACK.md` in
the cognic-agentos repo.
