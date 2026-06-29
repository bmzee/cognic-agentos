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

## Proof 1b-2 — attempt 1 (BAR 0 BLOCKED)

**2026-06-26 — harness defect (proof-harness build-context bug; NOT an AgentOS substrate or kernel finding; the proof is NOT redefined downward).**

> Proof 1b-2 attempt 1 — BAR 0 BLOCKED: AS image build failed because `Dockerfile.as` copied `tests/integration/...` from repo-root context, but `.dockerignore` excludes `tests/`. No Bar 1/Bar 2 result yet.

- **Classification:** proof-**harness** defect, not a substrate/kernel finding. The deployed kernel was never reached — the failure is at image build (runner step 4/11, `docker build -f infra/proof-1b-2/Dockerfile.as`), before `kind create` / `helm install`. Proof 1b-2 is **paused at BAR 0**, not downgraded; the Bar 1 (carve-out checkpoint) and Bar 2 (full governed loop) definitions are unchanged.
- **Root cause:** the AS image built with the **repo-root** context and `COPY tests/integration/pack_loop/_local_as.py /app/_local_as.py`. `.dockerignore` line 26 (`tests/`) excludes `tests/` from every repo-root build context (prod images ship no test code), so the COPY source was filtered out of the context → `"/tests/integration/pack_loop/_local_as.py": not found` → the build failed. (The MCP-server image copies from `examples/` — not excluded — and the agentos-proof image already builds with the `infra/proof-1b-2/` context, so only the AS image was affected.)
- **Fix (proof-harness only, no `src/` change):** vendor `_local_as.py` into the `infra/proof-1b-2/` build context — mirroring the existing `Dockerfile.agentos-proof` copy-into-context pattern. `Dockerfile.as` now `COPY _local_as.py /app/_local_as.py` (context-relative); the runner `cp`s the fixture into `infra/proof-1b-2/` and builds `Dockerfile.as` with context `infra/proof-1b-2` (cleaned up in `cleanup()`). A structural regression guard (`tests/unit/proof_1b_2/test_proof_images.py::test_no_proof_dockerfile_copies_from_excluded_dir`) now fails if any proof Dockerfile built with the repo-root context COPYs from a `.dockerignore`-excluded directory, so this class cannot recur.
- **Next:** re-run the operator proof (`COGNIC_RUN_PROOF_1B2=1 bash infra/proof-1b-2/run-proof-1b-2.sh`) to reach Bar 1 → Bar 2.

## Proof 1b-2 — attempt 2 (BAR 0 BLOCKED — build-context fix validated)

**2026-06-26 — harness defect (proof-harness Vault-token config drift; NOT an AgentOS substrate or kernel finding; the proof is NOT redefined downward).**

> Proof 1b-2 attempt 2 — BAR 0 BLOCKED (the build-context fix is validated: the run cleared all 4 image builds, `kind`, and the 6 backends to reach step 7/11). The Vault seed failed `403 invalid token` because `seed-vault.sh` + the Helm values used `proof1b2-root-token`, but the reused `backends.yaml` Vault dev server boots with `VAULT_DEV_ROOT_TOKEN_ID=smoke-root-token`. No Bar 1/Bar 2 result yet.

- **Classification:** proof-**harness** config drift, not a substrate/kernel finding. The deployed kernel was reached (the chart installed) but the Vault seed (runner step 7/11, before Bar 1) 403'd. Proof 1b-2 is **paused at BAR 0**, not downgraded; the Bar 1 / Bar 2 definitions are unchanged.
- **Root cause:** the proof reuses the chart's shared `infra/charts/agentos/ci/smoke/backends.yaml` Vault, which boots with `VAULT_DEV_ROOT_TOKEN_ID=smoke-root-token` (line 99). But `seed-vault.sh` (writes Vault) and `proof-1b-2-values.yaml` (the kernel's read token) both used `proof1b2-root-token` — so every `vault` call (and the kernel's Vault read) is rejected. (The 1b-1 overlay carried the same class of assumption — `proof1b-root-token` — but 1b-1 was blocked on substrate packaging before reaching the Vault seed, so 1b-2 is the first to hit it.)
- **Fix (proof-harness only, no `src/` change):** align the proof to the reused backend — `seed-vault.sh` + `proof-1b-2-values.yaml` now use `smoke-root-token` (the shared `backends.yaml` is NOT mutated). A structural guard (`tests/unit/proof_1b_2/test_proof_seeds.py::test_vault_token_matches_the_reused_backend_root_token`) now pins `seed-vault.sh` token == values `vaultToken` == `backends.yaml` `VAULT_DEV_ROOT_TOKEN_ID`, so this drift cannot recur.
- **Next:** re-run the operator proof to reach Bar 1 → Bar 2.

## Proof 1b-2 — attempt 3 (BAR 0 BLOCKED — Vault-token fix validated; deploy-substrate src-readability gap)

**2026-06-26 — deploy-substrate robustness gap (the kernel base image `infra/agentos/Dockerfile`, exposed by the proof; affects any deploy built from a restrictive umask, NOT proof-only, NOT a kernel runtime `src/cognic_agentos/` change).**

> Proof 1b-2 attempt 3 — BAR 0 BLOCKED (the Vault-token fix is validated: the run cleared the Vault seed + helm install to step 9/11). The non-hook migration Job failed: `PermissionError: [Errno 13] Permission denied: '/app/src/cognic_agentos/db/migrations/versions/20260625_0012_mcp_override_and_allowlist.py'`. No Bar 1/Bar 2 result yet.

- **Classification:** deploy-**substrate** robustness gap (the kernel base image), surfaced by the proof. The migrate Job (`alembic upgrade head`) runs as the non-root `cognic` user (UID 10001) and reads migrations from `/app/src/cognic_agentos/db/migrations` (alembic `script_location`). Still **paused at BAR 0**; Bar 1 / Bar 2 definitions unchanged.
- **Root cause:** migration `0012` was mode `600` (owner-only) in the build context (a restrictive umask; git does not track the read bit, so a standard `022` umask would have produced `644`). The base image `COPY --chown=root:cognic src ./src` then chmods `/app/policies` + `/app/alembic.ini` world-readable but **NOT `/app/src`** — even though the Dockerfile comment states the source should be "readable by cognic" and alembic reads it as non-root. So `/app/src/.../0012.py` landed `root:cognic 600`, `cognic` could not read it; alembic read the `644` older migrations and tripped on `0012`. The deploy-substrate packaging test verified the files *exist* + that policies/alembic are world-readable, but never that `/app/src` is — so it could not catch this.
- **Fix (deploy-substrate, both runtime stages of `infra/agentos/Dockerfile`):** add `/app/src` to the existing `chmod -R a+rX /app/policies /app/alembic.ini` — closing the inconsistency for every deploy regardless of the build-context umask. `tests/unit/infra/test_image_packaging.py` now asserts `/app/src` gets the same world-readable guarantee. (Proof-only `chmod` in `Dockerfile.agentos-proof` was rejected — it would mask the same failure a bank could hit from a restrictive umask.)
- **Next:** re-run the operator proof to reach Bar 1 → Bar 2.

## Proof 1b-2 — attempt 4 (BAR 1.1 BLOCKED — full setup validated; AS allow-list trailing-slash mismatch)

**2026-06-26 — proof-harness seed value mismatch (the AS allow-list issuer form; NOT a kernel finding — the kernel's exact-string issuer comparison is RFC 8414-correct; the proof is NOT redefined downward).**

> Proof 1b-2 attempt 4 — BAR 1.1 BLOCKED. **All setup is now green** (the src-readability fix validated: migrate Job ✓, MCP/AS manifests ✓, DB seed ✓, rollout ✓ — we reached the first governed-path Bar). Bar 1.1's `list_tools` returned `502 {"detail":{"reason":"mcp_as_not_allowlisted"}}`; `discovery_status` = `refused`. The carve-out itself works (PRM-discovery resource leg reached the private ClusterIP `10.96.0.50`); the AS allow-list gate refused.

- **Classification:** proof-**harness** seed value mismatch, NOT a kernel finding. The plugin registered (trust-side ✓); the failure is invoke-side at the AS allow-list. The kernel's exact-string issuer comparison (`mcp_authz.py:753` `s in allowed_servers`) is correct per RFC 8414 (issuer identifiers compared by simple string comparison). Still **paused at BAR 1.1**; Bar 1 / Bar 2 definitions unchanged.
- **Root cause:** the MCP server (FastMCP) wraps the AS issuer in pydantic `AnyHttpUrl`, which normalises `http://192.88.99.9:9000` → `http://192.88.99.9:9000/` (verified: `str(AnyHttpUrl('http://192.88.99.9:9000')) == 'http://192.88.99.9:9000/'`). So its PRM advertises `authorization_servers: ["http://192.88.99.9:9000/"]` (with the trailing slash), but `seed-vault.sh` seeded the allow-list as `["http://192.88.99.9:9000"]` (no slash). The kernel's exact-string membership test then refuses with `mcp_as_not_allowlisted`. The diagnostic capture (the re-curled 502 body + `discovery_status=refused` from `/system/plugins`) pinned it.
- **Fix (proof-harness only, no `src/` change):** `seed-vault.sh` now seeds the allow-list entry as `${AS}/` (the `AnyHttpUrl`-normalised form the PRM actually advertises). A structural guard (`tests/unit/proof_1b_2/test_proof_seeds.py::test_vault_seed_allowlist_entry_carries_the_anyhttpurl_trailing_slash`) pins the slash-suffixed entry. The downstream (AS discovery, OAuth-creds path, token `aud`) is unaffected by the slash — AS discovery inserts `/.well-known/...` at the root either way, and the creds path + audience are netloc/resource-based.
- **Operator-footgun observation (recorded, not fixed — NOT proposing a kernel change):** anyone allow-listing a FastMCP-based AS must use the exact `AnyHttpUrl`-normalised issuer (with the trailing slash), or the allow-list silently won't match. The kernel behavior is spec-compliant; the product may later want issuer-normalisation at the allow-list boundary or operator docs.
- **Next:** re-run the operator proof to continue Bar 1 → Bar 2.

## Proof 1b-2 — attempt 5 (BAR 1.1 BLOCKED — governed loop PROVEN; runner evidence-surface correction)

**2026-06-26 — proof-harness evidence-surface correction (the runner's Bar 1.1/1.2 audit assertions grepped pod stdout; NOT a kernel finding; the governed loop demonstrably works; the proof is NOT redefined downward).**

> Proof 1b-2 attempt 5 — BAR 1.1 BLOCKED on the *assertion*, not the *behaviour*. The slash fix landed: the post-run re-curl shows `list_tools` → **HTTP 200** with the real tool (`search_policy_docs`) AND `discovery_status` → **auth_ready** — the governed MCP loop completes end-to-end (PRM discovery → AS allow-list permit → AS discovery → token acquire → authenticated list_tools). The runner's Bar 1.1 still `FAIL`ed: `audit.mcp_allowlist_permitted did not fire` — because it grepped pod **stdout** for that event.

- **Classification:** proof-**harness** evidence-surface error, NOT a kernel finding and NOT a proof downgrade. The carve-out + OAuth + invoke all work (200 + auth_ready prove it). The runner just looked in the wrong place. This is the "Bar 1.1 log-surface risk" flagged before the run.
- **Root cause:** `audit.mcp_allowlist_permitted` is a DD-2 audit-store event — `mcp_authz.py:1233` `self._audit.append(AuditEvent(..., payload={leg, host, resolved_ips}))` — persisted to the **`audit_event` table**, NOT logged to stdout (`AuditStore.append` never logs the event). The runner did `LOGS="$(kubectl logs deploy/rel-agentos)"; grep audit.mcp_allowlist_permitted`, which can never match. Bar 1.2 had the same class of error: `mcp_discovery_url_refused` is a raised `MCPAuthzError` whose reason lands in the HTTP response **body** (not stdout), and `refused_component=host_address` is an exception attr surfaced nowhere in the body.
- **Fix (proof-harness only, no `src/` change):** correct the evidence surfaces. Bar 1.1 → `psql` the `audit_event` table (`SELECT payload::text WHERE event_type='audit.mcp_allowlist_permitted'`, assert it carries `10.96.0.50`; text-cast avoids a `jsonb`-operator assumption). Bar 1.2 → assert `mcp_discovery_url_refused` in the captured response **body** + `discovery_status=refused` via `/system/plugins` (replacing the unobservable `host_address` stdout grep with the same API evidence model Bar 2 uses for `auth_ready`). Bar 2 was already pure-API (the right surface). A new guard (`test_proof_runner.py::test_bar1_evidence_reads_db_and_api_surfaces_not_stdout`) pins the DB + API surfaces so a refactor can't revert to the stdout grep.
- **Next:** re-run the operator proof — Bar 1.1 should pass on the DB query, Bar 1.2 on the refusal + discovery_status=refused, then Bar 2 (`call_tool` is the only piece not yet exercised).

## Proof 1b-2 — PASS (Bar 1 + Bar 2, full governed loop)

**2026-06-26 — Proof 1b-2 PASSED. The deployed governed MCP invocation loop is proven end-to-end.**

> `RUN_EXIT=0` — `BAR 1 PASS` + `PROOF 1b-2 (BAR 2) PASS`. Five proof-harness/substrate findings (attempts 1–5) cleared, each pinned by a regression guard; zero kernel (`src/cognic_agentos/`) changes; the proof was never redefined downward.

- **Bar 1.1 (permit):** `audit.mcp_allowlist_permitted` persisted to the `audit_event` table carrying host `10.96.0.50` — the PR-2b-1 operator override + exact-IP allow-list carve-out reached the private ClusterIP.
- **Bar 1.2 (load-bearing):** with the allow-list row removed + a cold restart, the fresh `list_tools` refused `HTTP 502` + `mcp_discovery_url_refused` (response body) + `discovery_status=refused` (`/system/plugins`) — proving the carve-out is the ONLY path to the private MCP Service.
- **Bar 1.3:** re-seed + cold restart → clean state → `BAR 1 PASS`.
- **Bar 2 (completion):** `list_tools` → 200 with the real tool (`search_policy_docs`), `call_tool` → 200, `discovery_status=auth_ready` → `PROOF 1b-2 (BAR 2) PASS`. The full governed path runs: PRM discovery → AS allow-list permit → AS discovery → OAuth token acquire → authenticated `list_tools` + `call_tool` against the override-pinned private ClusterIP, with the OAuth legs reaching the emulated-external (public-shaped, kube-proxy-intercepted) AS.
- **Findings cleared (all proof-harness/substrate, no kernel change):** (1) `.dockerignore` build-context for the AS image; (2) Vault root-token alignment (`smoke-root-token`); (3) deploy-substrate `/app/src` readability (the base-image `chmod -R a+rX`); (4) AS allow-list `AnyHttpUrl` trailing-slash; (5) runner evidence-surface (`audit_event` table + `/system/plugins` API vs pod stdout). Each fix shipped with a structural guard so the class cannot recur.

## M3-E1 — external-pack authoring enablement (git-pinned kernel) — PASS (with closeout fix)

**2026-06-27 — M3-E1 proven: a clean external pack repo obtains the unpublished AgentOS authoring/governance CLI via the git-pinned install and runs `agentos validate`. The operator verify exposed a real Python-version fragility, fixed in the same closeout.**

> M3-E1 is the kernel-side enablement before the first external pack repo (`cognic-tool-oracle-schema`, M3-E2): the unpublished kernel (public repo; no PyPI/release artifact) is consumed by a generated pack via `cognic-agentos @ git+https://github.com/bmzee/cognic-agentos@v0.0.1`. PR #106 fixed the four scaffolds (CI + pyproject) to emit the git-pinned form; `v0.0.1` was cut (annotated) from green `main @ d174b74`.

### Run metadata
- **AgentOS tag:** `v0.0.1` (annotated, on the green merge commit `d174b74`)
- **Pack shape:** the proven `examples/cognic-tool-search` (a FastMCP server with NO AgentOS runtime dependency), staged as a clean external repo OUTSIDE the kernel tree
- **Date:** 2026-06-27
- **Command:** `COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT=1 COGNIC_AGENTOS_GIT_REF=v0.0.1 bash infra/external-pack-authoring/verify.sh` (operator-run, env-gated; sandbox-network override for the git fetch)

### The proof + the finding (honest)
1. **First raw run exposed a Python-3.13 fragility.** The original `verify.sh` created its venv with `python3 -m venv` — the *system* python, 3.13.1 on the operator box. The git-install of `cognic-agentos @ v0.0.1` then failed: `ERROR: Package 'cognic-agentos' requires a different Python: 3.13.1 not in '<3.13,>=3.12'`. The git-install **mechanism worked** (it cloned the repo + checked out the `v0.0.1` tag + built metadata); only the venv's Python version was wrong.
2. **A clean Python-3.12 repro PASSED.** With a `uv venv --python 3.12` venv (Python 3.12.3), the same git-install of `cognic-agentos @ v0.0.1` installed cleanly, and `agentos validate` on the staged external pack → **`validate: PASS`** (the only output is the expected Wave-1 `identity_oasf_capability_set_missing` warning). A clean external repo *does* obtain the kernel CLI from the tag and run governance — the M3-E1 claim holds.
3. **Closeout fix makes the proof repeatable (branch `fix/external-pack-verify-py312`).** Two related Python-version findings, both fixed so the script + scaffolds encode the kernel's real range:
   - `verify.sh` now creates the venv with **`uv venv --python 3.12`** (not the system `python3`), so it cannot silently use a 3.13+ interpreter the kernel rejects. A structural test (`test_script_pins_python_312_venv`) pins the 3.12 venv + forbids `python3 -m venv`.
   - The four scaffold `pyproject.toml` templates now declare **`requires-python = ">=3.12,<3.13"`** (was `>=3.12`, which allowed 3.13) — matching the kernel's actual range so an author on 3.13 gets a clear constraint rather than a confusing install failure. (Lower severity in CI — the scaffold CI already pins `setup-python 3.12` — but the same root cause.) `test_scaffolded_pyproject_pins_requires_python` pins the range across all four kinds.
   - `verify.sh`'s host-tooling gate now checks **all four** binaries `agentos sign` shells out to (`cosign` / `syft` / `grype` / **`pip-licenses`**) — the fixed-script re-run surfaced that the original three-binary check let the script enter the sign branch on a host with cosign/syft/grype but not the license auditor, failing `sign-bundle` ungracefully instead of recording `tooling_absent`. `test_script_records_tooling_absent_not_silent_skip` now pins all four.

**Fixed-script re-run (the repeatable proof — `RUN_EXIT=0`).** `uv venv --python 3.12` → git-install `cognic-agentos @ v0.0.1` → `validate: PASS` → `SIGN_VERIFY=tooling_absent:pip-licenses` (cosign/syft/grype ARE present on this host; only the license auditor is absent → cleanly recorded, the script exits 0). The fixed `verify.sh` is green + repeatable.

### Honesty boundary
- **`validate: PASS` is proven**; `sign`/`verify` were **not run** in this proof — on this host `pip-licenses` (the 4th tool `agentos sign` shells out to) is absent, recorded as `tooling_absent:pip-licenses` (cosign/syft/grype ARE present). By design `validate` alone proves external CLI consumption; the full supply-chain bundle additionally needs all four binaries + a cosign identity, and Proof 1a already proved the full sign/verify path in-process. M3-E1's claim is **the git-pinned authoring CLI is externally consumable + `validate` runs** — NOT a full signed-pack deploy (that is Proof 1b, already passed) and NOT the external pack repo itself (that is M3-E2).
- The operator verify is **env-gated** + must run on a real machine (it git-installs + spins a venv); it caught a real environment fragility an always-on CI lane (pinned to 3.12) could not.

## M3-E2c / Proof 2 — deployed external tool pack (released `cognic-tool-oracle-schema@v0.1.0`) — PASS

**2026-06-29 — M3-E2c proven: the first SEPARATE-REPO tool pack, downloaded as its released signed artifact, deployed + governed through a kind/Helm AgentOS instance end-to-end (`discovery_status=auth_ready` + real `list_tools`/`call_tool`), with the per-tenant exact-IP allow-list carve-out load-bearing.**

> M3-E2c closes the M3 deployed leg: M3-E1 proved the git-pinned authoring CLI is externally consumable; M3-E2a/b shipped the FastMCP authoring path + the released `cognic-tool-oracle-schema` repo + signed release; M3-E2c (this) deploys that released pack into AgentOS and runs the governed MCP loop. It mirrors the Proof 1b-2 deployed topology (PR #103) but against a DOWNLOADED released external artifact instead of an in-tree example.

### Run metadata
- **Date:** 2026-06-29 (operator-run, env-gated)
- **Command:** `COGNIC_RUN_PROOF_1B2C=1 bash infra/proof-1b-2c/run-proof-1b-2c.sh` → **`RUNNER_EXIT=0`**
- **Released pack:** `cognic-tool-oracle-schema@v0.1.0` — a separate **public** GitHub repo (`bmzee/cognic-tool-oracle-schema`) with independent CI + a signed GitHub Release (the wheel + 7 attestations + `cosign.pub` as assets). Staged into the proof by **`gh release download v0.1.0` + sha256 verification** of the wheel + `cosign.pub` — NOT a local rebuild (acceptance criterion #1). Verified digests: wheel `cognic_tool_oracle_schema-0.1.0-py3-none-any.whl` sha256 `4ed1a44773696429acf6bd5e88d91fa966ab9c4a0a3dc80925bac179883b1beb`; `cosign.pub` sha256 `43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78`.
- **Topology:** kind, the default-adapters prod image; the 6 bundled backends + an **in-cluster seeded Oracle XE** (`gvenzl/oracle-xe:21-slim`, the built-in `XEPDB1` PDB, the `cognic.*` demo schema from a single-source seed) backing the pack's read-only schema tools; a private-ClusterIP MCP Service (`10.96.0.51`); an emulated-external **RS256/JWKS** Authorization Server at a genuine-global Service `externalIP` (`192.88.99.9:9000`, kube-proxy-intercepted, no real egress). Tenant `proof-1b-2c`. Boot-time trust registration of the staged released artifact (there is no runtime install API).
- **Run log:** the operator runner stdout was reviewed for this record; all 10 steps + both bars green, no `*_fail` fired. The durable evidence is recorded inline below (BAR 1 permit/refusal + BAR 2 completion markers).

### Bar 1 (checkpoint — the PR-2b-1 carve-out is load-bearing) — PASS
- **Bar 1.1 (permit):** with the `mcp_internal_host_allowlist` row seeded, the resource leg reaches the private ClusterIP and the permit persists as an `audit.mcp_allowlist_permitted` event carrying host **`10.96.0.51`** (read from the `audit_event` table).
- **Bar 1.2 (the must-have negative):** `DELETE` the allow-list row → restart to a **cold** pod (MCPHost caches the token + tool list per tenant) → the fresh probe is **refused**: **HTTP 502 + `mcp_discovery_url_refused`** in the response body + `GET /api/v1/system/plugins?tenant_id=proof-1b-2c` shows the `cognic-tool-oracle-schema` row at **`discovery_status=refused`**.
- **Bar 1.3:** re-seed the allow-list + cold restart → clean state. → `BAR 1 PASS`.

### Bar 2 (completion — full governed loop) — PASS
- `list_tools` 200 → `call_tool` `describe_table(owner=COGNIC, table=EMPLOYEES)` 200 returning the seeded `EMPLOYEES` column metadata (the `FULL_NAME` content assertion passed — a bare 200 was not accepted) → `GET /api/v1/system/plugins?tenant_id=proof-1b-2c` shows `cognic-tool-oracle-schema` at **`discovery_status=auth_ready`**. → `PROOF 1b-2c (BAR 2) PASS`.

### Live findings cleared (all harness/deploy-substrate — ZERO `src/cognic_agentos` kernel change)
The proof attempt surfaced four real gaps, each diagnosed + fixed + pinned by a regression before the green run; the kernel governance logic was unchanged:
1. **cosign/OPA download retry** (`infra/agentos/Dockerfile`, commit `ea8808f`) — a transient TLS eof (`curl` exit 56) killed the base-image build; added `--retry 5 --retry-delay 3 --retry-all-errors` to the two pinned binary fetches (the `sha256sum -c` verify is unchanged). The single deploy-substrate edit — infra, not a kernel `src/` change.
2. **XE readiness wait + diagnostics** (`run-proof-1b-2c.sh`, commit `944c1e0`) — the qemu-emulated XE first boot under kind exceeds the original 600s wait; bumped to 1200s + added an `xe_fail` capture (pod describe/logs → this file) so a miss is diagnosable, not a blind timeout.
3. **`ORACLE_DATABASE=XEPDB1` removal** (`manifests/oracle-xe.yaml`, commit `edbb3f1`) — that env made gvenzl try to `CREATE PLUGGABLE DATABASE XEPDB1`, colliding with the built-in PDB (`ORA-65012`) → `CrashLoopBackOff`. Confirmed by a plain-docker repro; removed (the seed `ALTER`s into the built-in XEPDB1; the DSN stays `oracle-xe:1521/XEPDB1`).
4. **Backend/XE startup sequencing + diagnostics** (`run-proof-1b-2c.sh`, commit `ac5c22b`) — once XE actually booted, its CPU-saturating emulated boot overlapped with the backend startup and starved the backends past the 300s wait; reordered to bring the backends up Available BEFORE applying XE + added a `backends_fail` capture.

### Honesty boundary
- "PASS" means the **first separate-repo tool pack** was **deployed + governed through AgentOS on `kind`** end-to-end: released signed artifact → boot-time trust registration → `discovery_status=auth_ready` → real `list_tools` + `call_tool`, with the allow-list carve-out load-bearing (permit ↔ removed-delta refusal).
- It does **NOT** claim the full production **AKS** platform (M15/M24), an **LLM-agent** loop (M8), or the **operator-grade install flow** (M4) — this proof still seeds the override / allow-list / OAuth creds via the proof harness (direct DB/Vault seed) and uses a proof-only fixed-actor binder. The 6 backends are the real bundled adapters; the Oracle XE is real (amd64-emulated on this arm64 host).
- **Zero `src/cognic_agentos` kernel changes** were needed for the proof loop. The only kernel-adjacent edit was the `infra/agentos/Dockerfile` cosign/OPA download-retry build hardening (a deploy-substrate robustness fix surfaced by the proof, not a governance change).
