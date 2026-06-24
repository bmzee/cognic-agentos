<!-- docs/VALIDATION-RESULTS.md -->
# AgentOS — Validation Results

**Proof 1a — real-app in-process pack-governance loop.**

> Proof 1a proves the pack-governance loop in the real composition root. Proof 1b
> proves the same signed pack in a kind/Helm deployed instance. 1a proves the loop
> **logic**; it does NOT claim "bank-deployed."

This is the first time the full **deploy → install a real signed pack → an agent does one
governed task → audit trail** loop has run end-to-end with a **real** pack against the real
composition root in-process. It supersedes the `docs/PROJECT_STATUS.md` headline gap
("the loop has never run end-to-end") with: **Proof 1a in-process proven; Proof 1b deploy
proof still pending.**

## Run metadata
- **AgentOS commit:** `e3a21d845d779b4438c368e8a58ed80444f3f866` (the `feat/pack-loop-proof-1a` branch; both kernel fixes below are in `main @ 566b534baa9b20c69ee1c65f3f2d461978c12e83`, which this branch is rebased onto)
- **Pack:** `cognic-tool-search` 0.1.0 (`examples/cognic-tool-search/`) — an in-tree but external-to-OS real MCP tool pack (built into a wheel, signed, installed as if external)
- **Date:** 2026-06-23
- **Toolchain:** cosign `v3.0.6`, syft `1.44.0`, grype `0.112.0`
- **Command:** `COGNIC_RUN_PACK_LOOP_PROOF=1 uv run pytest tests/integration/pack_loop/test_proof_1a_inprocess.py -v` → `1 passed`
- **Backend footprint:** in-memory relational (sqlite — the genuine hash-chain backend) + secret + vector + embedding + observability adapters, `local_fs` object store, `cache_driver="none"` (no Redis/scheduler/sandbox — a `read_only` MCP invoke touches none). No full Vault.

## Artifact digests
From the most recent in-process proof run's authoring output (`examples/cognic-tool-search/{dist,attestations}/`; the per-run cosign keypair is ephemeral, so `cosign.sig` varies per run — the wheel + SBOM are stable from source):
- wheel `cognic_tool_search-0.1.0-py3-none-any.whl` sha256: `16fa2387b393bebd50b1ffc53aeadc9f38b2a2f385a5e0209ddef6f35c4512ad`
- `cosign.sig` sha256: `3d94779873413b771c898b5d690ac20c4448aec5d452570c6535ecef200ddf3e` (ephemeral per-run key)
- `sbom.cdx.json` sha256: `081926895a2059a20ec5ebf5a5f727801c5d2d24ee5670fd3d25f44da343a5e0`
- SLSA `predicate.buildDefinition.externalParameters.sbom_digest_sha256`: `081926895a2059a20ec5ebf5a5f727801c5d2d24ee5670fd3d25f44da343a5e0` — **matches the `sbom.cdx.json` digest above**, confirming the SLSA provenance pins exactly the SBOM digest the runtime resolver reads.
- cosign 3.x posture: the produced `bundle.sigstore` is `base64Signature`-only (no `tlogEntries` / `rekorBundle`) — offline / no public-Rekor upload, per the cosign-3.x legacy-compat bridge (ADR-016).

## The 6 PASS assertions
All green (`COGNIC_RUN_PACK_LOOP_PROOF=1` run, real cosign/syft/grype):

1. [x] `agentos verify` exits 0 on the signed pack. *(Task 6 authoring helper — real sign → validate → verify.)*
2. [x] `build_and_populate_registry` registers `cognic-tool-search` **WITHOUT a fail-soft skip** (the core seam: the real runtime trust pipeline accepted real `agentos sign` output, with `require_cosign=True`). *(This is the assertion that initially turned the proof RED on the in-toto contract bug below — green once fixed.)*
3. [x] `list_tools` reports `search_policy_docs`.
4. [x] `call_tool("search_policy_docs", {"query": "retention"})` via `POST /api/v1/mcp/servers/{id}/tools/call` (bound `Actor` with `mcp.tool.invoke`) returns the deterministic result.
5. [x] A decision-history/audit row exists for the invocation; the hash chain verifies (`ChainVerifier(...).walk().is_clean`).
6. [x] An evidence pack exports + re-verifies (tamper-evident): a real `cosign`-signed ISO-42001 evidence-pack `.tar.gz` with the exact 5-member set `{manifest.json, manifest.json.sig, manifest.json.bundle.sigstore, audit_event.jsonl, decision_history.jsonl}` — the `decision_history.jsonl` is the hash-chained tamper-evident core.

**Green ⇔ the real authoring trust pipeline produces artifacts the real runtime trust pipeline accepts.**

## Findings recorded by this proof

### Two real kernel bugs surfaced (the proof's headline value — both now FIXED on `main`)
The startup-discovery slice (PR #92) unit-proved the runtime trust pipeline against **hand-built** attestations. Exercising it against **real** `agentos sign` output for the first time surfaced two genuine author↔runtime seams that hand-built fixtures had masked:

1. **cosign 3.x broke the kernel signing path.** Building the real `agentos sign` authoring step (Task 6) found that cosign v3.0.6 deprecates + ignores `--output-signature` and uploads to public Rekor by default — so `agentos sign`'s post-check failed and the detached `cosign.sig` was never produced; the supply-chain signing path was pinned to cosign 2.x. **Fixed** as a tight critical-controls slice (the cosign 3.x legacy-compat bridge, Fork A — keep `cosign.sig` + offline bundle via verified compat flags) → **merged PR #94 @ `201e190`**, ADR-016 amended.
2. **The in-toto Wave-1 layout contract disagreed author↔runtime.** With cosign fixed, the full loop (Task 7) then surfaced that `cli/sign.py` emits a Wave-1 *simplified* in-toto layout (`_type = "in-toto-layout/v1-wave1-simplified"`, intentionally omitting `steps`/`expires`) but `protocol/supply_chain.py:_verify_intoto` hard-required `steps`+`expires` → **every real signed pack was refused at registration with `intoto_tampered`** (assertion 2). **Fixed** as a tight critical-controls slice (option b — the runtime verifies the declared simplified contract by branching on `_type`; single-sourced constant; structural-only `pack_kind`) → **merged PR #95 @ `566b534`**, ADR-016 amended.

Both were fixed with full discipline (RED proof → contract decision → focused CC fix → dedicated spec + code-quality reviews → green CI → squash-merge), each as its own reviewable kernel PR — not folded into this proof.

### By-design findings (spec §10, all resolved cleanly)
- **Two consumers, one manifest (LOCK 2):** the CLI reads the top-level blocks from the on-disk manifest; the runtime reads the SAME manifest as package data inside the wheel (`force-include`). Result: **accepted** — the runtime read the in-wheel manifest and registered the pack.
- **Wheel co-location provisioning:** `agentos sign` writes the 7 attestations to `<pack>/attestations/` and signs the wheel in place in `<pack>/dist/`; the runtime resolver requires all 8 artifacts co-located under `<root>/<dist>/<version>/`. Result: **bridged cleanly** by a provisioning copy with no renames (`_authoring.provision_attestation_tree`) — the recorded author↔runtime layout gap; the names already match the resolver exactly.
- **`[tool.cognic.mcp]`-on-tool-pack validate tolerance:** Result: **accepted** — `agentos validate` does not refuse a tool pack for carrying the runtime-consumed `[tool.cognic.mcp]` block; the runtime is the real consumer.
- **Runtime OAuth/PRM auth path:** the real `acquire_token` path (PRM discovery → per-tenant AS allow-list → token fetch → audience validation → scope-subset enforcement) was exercised end-to-end against a local test AS in `runtime_profile = "dev"`. Result: **accepted**.

### Diagnostic-fallback (spec §9 (b))
Not used — the full real pipeline ran (real cosign/syft/grype sign + real runtime registration). No hand-built-attestation diagnostic fallback was needed.

## Honesty boundary
- "Done / ✅" here means the loop ran **green in the real composition root, in-process**. It does **NOT** mean deployed-and-proven on a cluster — that is **Proof 1b** (kind/Helm, the same signed pack, boot-time registration via image-bake or mounted volume + pod restart; there is no runtime install API).
- The backends are real-but-lightweight (sqlite for the hash chain, `local_fs` object store, a test secret adapter, a local test OAuth/PRM server) — chosen so the proof fails only on AgentOS integration, not on infrastructure. Production deployment uses the bundled Postgres / Vault / object-store adapters per ADR-009.
- Sequenced follow-ons: **Proof 1b** (kind/Helm, same signed pack — the deployment proof), split into **Proof 1b-1** (deployed trust registration — re-framed under PR-1 trust-register-then-defer; see the section below) + **Proof 1b-2** (deployed endpoint/invoke — needs the PR-2 operator URL override + internal-host allow-list), then **Proof 2** (extract `cognic-tool-search` to its own repo with independent pack CI).

## Proof 1b-1 — deployed trust registration, re-framed under PR-1 (ADR-002 trust-register-then-defer)

Proof 1b-1 is the **deployed trust-registration axis** of Proof 1b: a kind/Helm-deployed AgentOS kernel must trust-register the signed `cognic-tool-search` pack at boot, observed via `GET /api/v1/system/plugins`. (Proof 1b-2 — the deployed endpoint/invoke axis — is separate; see the boundary below.)

**What the deployed run established** (the `feat/pack-loop-proof-1b` harness @ `2125b22`, 2026-06-24, after the deployment-substrate packaging fix PR #98). The deployed kernel **booted, ran its migrations, loaded the OPA policy bundles, reached the real trust/admission path, and verified the pack's signature + attestations** — the **offline trust-verification portion reached signature + attestation verification on a cluster** (completed trust registration awaits the PR-1 deployed re-run; the old run did not register). The pack was then **refused at registration** (`status: refused_at_registration`, `refusal_reason: mcp_discovery_url_refused`, `attestation_grade: null`) because the **old** boot-time registration ran an OAuth/PRM **discovery probe** of the pack's MCP `server_url` (`http://127.0.0.1:8765/mcp` — a loopback URL), which the prod-profile **SSRF guard correctly rejected**. The signature + attestations were independently valid; the refusal was purely about the *runtime discovery URL*, not trust.

**The PR-1 re-frame** (ADR-002 "trust-register-then-defer", Slices 1 + 2 — landed on `feat/adr-002-discovery-decoupling`). That refusal exposed a model error: a **runtime-endpoint** concern (the discovery probe) was gating **trust** registration. PR-1 decouples them — registration is now **trust-only** (the OAuth-PRM discovery/network probe is removed from registration and runs at invoke), and a separate **`discovery_status`** axis (`unprobed` / `auth_ready` / `refused` / `unreachable`) carries endpoint reachability. Under this model, the deployed Proof 1b-1 trust registration is:

- **`status == "registered"`** — the signature-verified pack registers (no registration-time probe to refuse it), and
- **`discovery_status == "unprobed"`** — no invoke has run yet, so the endpoint axis is untouched.

**Honesty boundary (no overclaim).** This re-frame is the *model* outcome implied by the deployed run (which reached offline signature + attestation verification) plus the PR-1 decoupling (which removes the mis-placed probe). It is **not** yet a deployed-and-re-run result: the PR-1 kernel (Slices 1 + 2) is on the branch, not yet baked into a deployed image — a deployed re-run with the PR-1 kernel is the verification that directly confirms `status == "registered"` on a cluster. Proof 1b-1 is now **defined as deployed trust registration** (after decoupling); it is **confirmed only after** the deployed PR-1 re-run observes `registered` + `unprobed`. It does **not** claim endpoint health (`auth_ready` ≠ "healthy") or **deployed task completion** — those are Proof 1b-2.

**Why the loopback finding still matters (→ Proof 1b-2 + PR 2).** The `server_url` is **environment-specific**: `127.0.0.1` is correct in-process (Proof 1a) but correctly refused deployed. A deployed *invoke* (Proof 1b-2 — `discovery_status` reaching `auth_ready` + a real `list_tools` / `call_tool`) needs an **SSRF-safe, reachable, in-cluster MCP Service** — i.e. an operator `server_url` override + a per-tenant, default-deny **internal-host allow-list**, validated by the *same* SSRF guard. That work is **PR 2** (a separate workstream with its own threat-model pass); the pack's loopback URL is **not** edited to force Proof 1b-1 green.
