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

## Proof M4 — migration Job FAILURE (2026-07-01T08:05:33Z)

- Failed step: `agentos-migrate did not complete within 300s`
- migrate job + pod (-o wide):
```
error: selectors and the all flag cannot be used when passing resource/name arguments
```
- migrate job describe:
```
Name:                        agentos-migrate
Namespace:                   cognic-proofm4
Selector:                    batch.kubernetes.io/controller-uid=c98b126a-da89-4edf-93ad-62e65b5a3e6d
Labels:                      batch.kubernetes.io/controller-uid=c98b126a-da89-4edf-93ad-62e65b5a3e6d
                             batch.kubernetes.io/job-name=agentos-migrate
                             controller-uid=c98b126a-da89-4edf-93ad-62e65b5a3e6d
                             job-name=agentos-migrate
Annotations:                 <none>
Parallelism:                 1
Completions:                 1
Completion Mode:             NonIndexed
Suspend:                     false
Backoff Limit:               1
TTL Seconds After Finished:  600
Start Time:                  Wed, 01 Jul 2026 13:00:33 +0500
Pods Statuses:               0 Active (0 Ready) / 0 Succeeded / 2 Failed
Pod Template:
  Labels:  batch.kubernetes.io/controller-uid=c98b126a-da89-4edf-93ad-62e65b5a3e6d
           batch.kubernetes.io/job-name=agentos-migrate
           controller-uid=c98b126a-da89-4edf-93ad-62e65b5a3e6d
           job-name=agentos-migrate
  Containers:
   migrate:
    Image:           cognic-agentos:proofm4
    Port:            <none>
    Host Port:       <none>
    SeccompProfile:  RuntimeDefault
    Command:
      sh
      -c
    Args:
      set -eu
      if [ -z "${COGNIC_DATABASE_URL:-}" ]; then
        echo "FATAL: COGNIC_DATABASE_URL is unset — refusing to run migrations" >&2
        exit 1
      fi
      exec alembic upgrade head

    Environment Variables from:
      rel-agentos-config  ConfigMap  Optional: false
    Environment:
      COGNIC_DATABASE_URL:  <set to the key 'COGNIC_DATABASE_URL' in secret 'rel-agentos-secrets'>  Optional: false
    Mounts:
      /tmp from tmp (rw)
  Volumes:
   tmp:
    Type:          EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:     <unset>
  Node-Selectors:  <none>
  Tolerations:     <none>
Events:
  Type     Reason                Age    From            Message
  ----     ------                ----   ----            -------
  Normal   SuccessfulCreate      5m     job-controller  Created pod: agentos-migrate-8w2l5
  Normal   SuccessfulCreate      4m47s  job-controller  Created pod: agentos-migrate-4wlmq
  Warning  BackoffLimitExceeded  4m43s  job-controller  Job has reached the specified backoff limit
```
- migrate logs (tail 180):
```
Found 2 pods, using pod/agentos-migrate-8w2l5
Traceback (most recent call last):
  File "/opt/venv/bin/alembic", line 10, in <module>
    sys.exit(main())
             ^^^^^^
  File "/opt/venv/lib/python3.12/site-packages/alembic/config.py", line 1047, in main
    CommandLine(prog=prog).main(argv=argv)
  File "/opt/venv/lib/python3.12/site-packages/alembic/config.py", line 1037, in main
    self.run_cmd(cfg, options)
  File "/opt/venv/lib/python3.12/site-packages/alembic/config.py", line 971, in run_cmd
    fn(
  File "/opt/venv/lib/python3.12/site-packages/alembic/command.py", line 463, in upgrade
    script = ScriptDirectory.from_config(config)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/opt/venv/lib/python3.12/site-packages/alembic/script/base.py", line 181, in from_config
    prepend_sys_path = config.get_prepend_sys_paths_list()
                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/opt/venv/lib/python3.12/site-packages/alembic/config.py", line 630, in get_prepend_sys_paths_list
    self._get_toml_config_value("prepend_sys_path", None),
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/opt/venv/lib/python3.12/site-packages/alembic/config.py", line 494, in _get_toml_config_value
    self.toml_alembic_config.get(name, USE_DEFAULT)
    ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/opt/venv/lib/python3.12/site-packages/sqlalchemy/util/langhelpers.py", line 1123, in __get__
    obj.__dict__[self.__name__] = result = self.fget(obj)
                                           ^^^^^^^^^^^^^^
  File "/opt/venv/lib/python3.12/site-packages/alembic/config.py", line 277, in toml_alembic_config
    with open(self._toml_file_path, "rb") as f:
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
PermissionError: [Errno 13] Permission denied: 'pyproject.toml'
```
- namespace events (tail 120):
```
LAST SEEN   TYPE      REASON                 OBJECT                              MESSAGE
8m23s       Normal    ScalingReplicaSet      deployment/ollama                   Scaled up replica set ollama-84dd449db5 from 0 to 1
8m23s       Normal    ScalingReplicaSet      deployment/langfuse                 Scaled up replica set langfuse-77458bd486 from 0 to 1
8m23s       Normal    ScalingReplicaSet      deployment/vault                    Scaled up replica set vault-564b656fbf from 0 to 1
8m23s       Normal    SuccessfulCreate       replicaset/vault-564b656fbf         Created pod: vault-564b656fbf-4lcvf
8m23s       Normal    Scheduled              pod/vault-564b656fbf-4lcvf          Successfully assigned cognic-proofm4/vault-564b656fbf-4lcvf to cognic-proofm4-control-plane
8m23s       Normal    ScalingReplicaSet      deployment/qdrant                   Scaled up replica set qdrant-54644949b7 from 0 to 1
8m23s       Normal    SuccessfulCreate       replicaset/qdrant-54644949b7        Created pod: qdrant-54644949b7-v8vlc
8m23s       Normal    Scheduled              pod/qdrant-54644949b7-v8vlc         Successfully assigned cognic-proofm4/qdrant-54644949b7-v8vlc to cognic-proofm4-control-plane
8m23s       Normal    ScalingReplicaSet      deployment/postgres                 Scaled up replica set postgres-74b77c4f75 from 0 to 1
8m23s       Normal    SuccessfulCreate       replicaset/postgres-74b77c4f75      Created pod: postgres-74b77c4f75-7d68s
8m23s       Normal    Scheduled              pod/postgres-74b77c4f75-7d68s       Successfully assigned cognic-proofm4/postgres-74b77c4f75-7d68s to cognic-proofm4-control-plane
8m23s       Normal    Scheduled              pod/langfuse-77458bd486-4wd55       Successfully assigned cognic-proofm4/langfuse-77458bd486-4wd55 to cognic-proofm4-control-plane
8m23s       Normal    SuccessfulCreate       replicaset/ollama-84dd449db5        Created pod: ollama-84dd449db5-v82bk
8m23s       Normal    Scheduled              pod/ollama-84dd449db5-v82bk         Successfully assigned cognic-proofm4/ollama-84dd449db5-v82bk to cognic-proofm4-control-plane
8m23s       Normal    ScalingReplicaSet      deployment/litellm                  Scaled up replica set litellm-854bfdcb5d from 0 to 1
8m23s       Normal    SuccessfulCreate       replicaset/litellm-854bfdcb5d       Created pod: litellm-854bfdcb5d-h9q74
8m23s       Normal    Scheduled              pod/litellm-854bfdcb5d-h9q74        Successfully assigned cognic-proofm4/litellm-854bfdcb5d-h9q74 to cognic-proofm4-control-plane
8m23s       Normal    SuccessfulCreate       replicaset/langfuse-77458bd486      Created pod: langfuse-77458bd486-4wd55
8m22s       Normal    Started                pod/qdrant-54644949b7-v8vlc         Container started
8m22s       Normal    Created                pod/qdrant-54644949b7-v8vlc         Container created
8m22s       Normal    Pulled                 pod/litellm-854bfdcb5d-h9q74        Container image "ghcr.io/berriai/litellm:main-stable" already present on machine and can be accessed by the pod
8m22s       Normal    Created                pod/litellm-854bfdcb5d-h9q74        Container created
8m22s       Normal    Started                pod/litellm-854bfdcb5d-h9q74        Container started
8m22s       Normal    Created                pod/postgres-74b77c4f75-7d68s       Container created
8m22s       Normal    Started                pod/postgres-74b77c4f75-7d68s       Container started
8m22s       Warning   Unhealthy              pod/postgres-74b77c4f75-7d68s       Readiness probe failed: /var/run/postgresql:5432 - no response
8m22s       Normal    Pulled                 pod/qdrant-54644949b7-v8vlc         Container image "qdrant/qdrant:v1.17.1" already present on machine and can be accessed by the pod
8m22s       Normal    Pulled                 pod/postgres-74b77c4f75-7d68s       Container image "postgres:16-alpine" already present on machine and can be accessed by the pod
8m22s       Normal    Started                pod/vault-564b656fbf-4lcvf          Container started
8m22s       Normal    Created                pod/vault-564b656fbf-4lcvf          Container created
8m22s       Normal    Pulled                 pod/vault-564b656fbf-4lcvf          Container image "hashicorp/vault:1.18" already present on machine and can be accessed by the pod
8m22s       Warning   Unhealthy              pod/qdrant-54644949b7-v8vlc         Readiness probe failed: Get "http://10.244.0.6:6333/readyz": dial tcp 10.244.0.6:6333: connect: connection refused
8m21s       Warning   Unhealthy              pod/vault-564b656fbf-4lcvf          Readiness probe failed: Get "http://10.244.0.7:8200/v1/sys/health": dial tcp 10.244.0.7:8200: connect: connection refused
8m17s       Warning   BackOff                pod/langfuse-77458bd486-4wd55       Back-off restarting failed container langfuse in pod langfuse-77458bd486-4wd55_cognic-proofm4(b06c9a8e-c692-4ab6-8fd9-196c76196881)
8m7s        Normal    Pulled                 pod/langfuse-77458bd486-4wd55       Container image "langfuse/langfuse:2" already present on machine and can be accessed by the pod
8m7s        Normal    Created                pod/langfuse-77458bd486-4wd55       Container created
8m7s        Normal    Started                pod/langfuse-77458bd486-4wd55       Container started
8m6s        Warning   Unhealthy              pod/langfuse-77458bd486-4wd55       Readiness probe failed: Get "http://10.244.0.9:3000/api/public/health": dial tcp 10.244.0.9:3000: connect: connection refused
8m1s        Warning   Unhealthy              pod/litellm-854bfdcb5d-h9q74        Readiness probe failed: Get "http://10.244.0.10:4000/health/liveliness": dial tcp 10.244.0.10:4000: connect: connection refused
7m52s       Normal    Killing                pod/ollama-84dd449db5-v82bk         FailedPostStartHook
7m52s       Warning   FailedPostStartHook    pod/ollama-84dd449db5-v82bk         PostStartHook failed
7m47s       Warning   BackOff                pod/ollama-84dd449db5-v82bk         Back-off restarting failed container ollama in pod ollama-84dd449db5-v82bk_cognic-proofm4(1a71d39d-b643-4f39-aa91-25b689f3393f)
7m30s       Normal    Pulled                 pod/ollama-84dd449db5-v82bk         Container image "ollama/ollama:0.5.4" already present on machine and can be accessed by the pod
7m30s       Normal    Created                pod/ollama-84dd449db5-v82bk         Container created
7m30s       Normal    Started                pod/ollama-84dd449db5-v82bk         Container started
6m2s        Normal    Pulled                 pod/oracle-xe-6fbd6d88cc-79tg5      Container image "gvenzl/oracle-xe:21-slim" already present on machine and can be accessed by the pod
6m2s        Normal    SuccessfulCreate       replicaset/oracle-xe-6fbd6d88cc     Created pod: oracle-xe-6fbd6d88cc-79tg5
6m2s        Normal    Started                pod/oracle-xe-6fbd6d88cc-79tg5      Container started
6m2s        Normal    Created                pod/oracle-xe-6fbd6d88cc-79tg5      Container created
6m2s        Normal    ScalingReplicaSet      deployment/oracle-xe                Scaled up replica set oracle-xe-6fbd6d88cc from 0 to 1
6m2s        Normal    Scheduled              pod/oracle-xe-6fbd6d88cc-79tg5      Successfully assigned cognic-proofm4/oracle-xe-6fbd6d88cc-79tg5 to cognic-proofm4-control-plane
5m          Normal    SuccessfulCreate       job/agentos-migrate                 Created pod: agentos-migrate-8w2l5
5m          Normal    SuccessfulCreate       replicaset/rel-agentos-5d87df78f4   Created pod: rel-agentos-5d87df78f4-sh9nh
5m          Normal    Scheduled              pod/agentos-migrate-8w2l5           Successfully assigned cognic-proofm4/agentos-migrate-8w2l5 to cognic-proofm4-control-plane
5m          Normal    ScalingReplicaSet      deployment/rel-agentos              Scaled up replica set rel-agentos-5d87df78f4 from 0 to 1
5m          Normal    Scheduled              pod/rel-agentos-5d87df78f4-sh9nh    Successfully assigned cognic-proofm4/rel-agentos-5d87df78f4-sh9nh to cognic-proofm4-control-plane
4m59s       Normal    Pulled                 pod/agentos-migrate-8w2l5           Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
4m59s       Normal    Created                pod/agentos-migrate-8w2l5           Container created
4m59s       Normal    Started                pod/agentos-migrate-8w2l5           Container started
4m47s       Normal    Pulled                 pod/agentos-migrate-4wlmq           Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
4m47s       Normal    Created                pod/agentos-migrate-4wlmq           Container created
4m47s       Normal    Started                pod/agentos-migrate-4wlmq           Container started
4m47s       Normal    SuccessfulCreate       job/agentos-migrate                 Created pod: agentos-migrate-4wlmq
4m47s       Normal    Scheduled              pod/agentos-migrate-4wlmq           Successfully assigned cognic-proofm4/agentos-migrate-4wlmq to cognic-proofm4-control-plane
4m43s       Warning   BackoffLimitExceeded   job/agentos-migrate                 Job has reached the specified backoff limit
102s        Normal    Pulled                 pod/rel-agentos-5d87df78f4-sh9nh    Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
102s        Normal    Started                pod/rel-agentos-5d87df78f4-sh9nh    Container started
102s        Normal    Created                pod/rel-agentos-5d87df78f4-sh9nh    Container created
100s        Warning   Unhealthy              pod/rel-agentos-5d87df78f4-sh9nh    Startup probe failed: Get "http://10.244.0.12:8000/api/v1/healthz": dial tcp 10.244.0.12:8000: connect: connection refused
24s         Warning   BackOff                pod/rel-agentos-5d87df78f4-sh9nh    Back-off restarting failed container agentos in pod rel-agentos-5d87df78f4-sh9nh_cognic-proofm4(d7384ac6-6cac-44e8-a074-d1145edc6416)
```

## Proof M4 — FAILURE (2026-07-01T08:14:37Z)

- Failed step: `BAR 1.1 create_draft (HTTP )`
- last API response (HTTP ):
```json
{"id":"6e1ee59a-9d97-4957-b5b1-e9f2ce7d935f","kind":"tool","pack_id":"cognic-tool-oracle-schema","display_name":"Cognic Oracle Schema (proof-m4)","state":"draft","tenant_id":"proof-m4","created_by":"proof-m4-author","last_actor":"proof-m4-author","created_at":"2026-07-01T08:14:37.401719Z","updated_at":"2026-07-01T08:14:37.401719Z"}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T08:14:31.856072+00:00","discovery_status":"unprobed"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":1,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
<none>
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 08:14:31,492", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 08:14:31,885", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 08:14:32,274", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b069f76966484316a30be44206738fcb", "trace_id": "30f5cc718e33a4f2ddc199405343fed9", "span_id": "551b5481c52d7b61", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.117, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 08:14:32,770", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-17ec7fdc66004207b959af70f71249a2", "trace_id": "79686cc1dfe31fbe894f41788af74d23", "span_id": "11464cc0d3be510a"}
{"ts": "2026-07-01 08:14:32,779", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-17ec7fdc66004207b959af70f71249a2", "trace_id": "79686cc1dfe31fbe894f41788af74d23", "span_id": "11464cc0d3be510a"}
{"ts": "2026-07-01 08:14:32,787", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-17ec7fdc66004207b959af70f71249a2", "trace_id": "79686cc1dfe31fbe894f41788af74d23", "span_id": "11464cc0d3be510a"}
{"ts": "2026-07-01 08:14:32,787", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-17ec7fdc66004207b959af70f71249a2", "trace_id": "79686cc1dfe31fbe894f41788af74d23", "span_id": "11464cc0d3be510a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.533, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 08:14:37,424", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e8e840f5460644be9ae8ae1618cd5b16", "trace_id": "a169c4795079165ea3d9fc5cd8d92697", "span_id": "d3f9544c4e6f83ff", "http_method": "POST", "http_path": "/api/v1/packs/drafts", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 24.396, "client_addr": "127.0.0.1"}
```

## Proof M4 — FAILURE (2026-07-01T09:03:09Z)

- Failed step: `BAR 1.4 approve (HTTP 412; body: {"detail":{"pack_kind":"tool","gates":[{"gate":"signature","outcome":"red","red_reason":"signature_blob_path_not_declared_in_manifest","evidence_pointer":null},{"gate":"evaluation","outcome":"evidence_not_attached","red_reason":"evaluation_evidence_not_attached","evidence_pointer":null},{"gate":"adversarial","outcome":"evidence_not_attached","red_reason":"adversarial_evidence_not_attached","evidence_pointer":null},{"gate":"owasp_conformance","outcome":"green","red_reason":null,"evidence_pointer":null},{"gate":"reviewer_acknowledgement","outcome":"green","red_reason":null,"evidence_pointer":null}],"all_green":false,"non_overridable_red_gates":["signature"],"override_refusal_reason":"non_overridable_red_gate"}})`
- last API response (HTTP 412):
```json
{"detail":{"pack_kind":"tool","gates":[{"gate":"signature","outcome":"red","red_reason":"signature_blob_path_not_declared_in_manifest","evidence_pointer":null},{"gate":"evaluation","outcome":"evidence_not_attached","red_reason":"evaluation_evidence_not_attached","evidence_pointer":null},{"gate":"adversarial","outcome":"evidence_not_attached","red_reason":"adversarial_evidence_not_attached","evidence_pointer":null},{"gate":"owasp_conformance","outcome":"green","red_reason":null,"evidence_pointer":null},{"gate":"reviewer_acknowledgement","outcome":"green","red_reason":null,"evidence_pointer":null}],"all_green":false,"non_overridable_red_gates":["signature"],"override_refusal_reason":"non_overridable_red_gate"}}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T09:03:03.714834+00:00","discovery_status":"unprobed"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":1,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
<none>
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 09:03:03,338", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 09:03:03,747", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 09:03:04,217", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-09228d6177974d069fa67a4ead63591d", "trace_id": "bd3acd1963bfa859e438e19166cb90ca", "span_id": "d9d7a0de82507e1d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.087, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:03:04,749", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a59bbc196a994adf95219331e5a31ba3", "trace_id": "10237c7adaa61251e7db4cf55457630c", "span_id": "49b94a816eb5147e"}
{"ts": "2026-07-01 09:03:04,758", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a59bbc196a994adf95219331e5a31ba3", "trace_id": "10237c7adaa61251e7db4cf55457630c", "span_id": "49b94a816eb5147e"}
{"ts": "2026-07-01 09:03:04,766", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a59bbc196a994adf95219331e5a31ba3", "trace_id": "10237c7adaa61251e7db4cf55457630c", "span_id": "49b94a816eb5147e"}
{"ts": "2026-07-01 09:03:04,766", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a59bbc196a994adf95219331e5a31ba3", "trace_id": "10237c7adaa61251e7db4cf55457630c", "span_id": "49b94a816eb5147e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.162, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:03:09,407", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0559f51acebd47e3a0ee512a83aae2b6", "trace_id": "3998d233c526a7704c446f00a6e8c330", "span_id": "bbf6249e0eeb875b", "http_method": "POST", "http_path": "/api/v1/packs/drafts", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 24.176, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:03:09,497", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9c1cd8809bf240ed818136261c4358c7", "trace_id": "3ef598d25c00d68eab1c8f49db5b21d4", "span_id": "e70378483b209d8b", "http_method": "POST", "http_path": "/api/v1/packs/drafts/1918f298-14ba-4716-be25-64ddbb5f40cb/submit", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 11.936, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:03:09,524", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ae0ac2b3dfbd4599af7f075d56fa17b5", "trace_id": "84dd1221af3f0b11bff7d03d17e9dfae", "span_id": "a13d58828536175b", "http_method": "POST", "http_path": "/api/v1/packs/1918f298-14ba-4716-be25-64ddbb5f40cb/claim", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 6.364, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:03:09,581", "level": "WARNING", "logger": "cognic_agentos.portal.api.packs.review_routes", "message": "portal.packs.approve_override_refused", "request_id": "portal-req-c3791a600ad14f65841fee9197df5464", "trace_id": "d8598b2690f04157da6d4f993f025269", "span_id": "b508654e4f5a1074", "reason": "non_overridable_red_gate", "actor_subject": "proof-m4-reviewer", "pack_id": "1918f298-14ba-4716-be25-64ddbb5f40cb"}
{"ts": "2026-07-01 09:03:09,581", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c3791a600ad14f65841fee9197df5464", "trace_id": "d8598b2690f04157da6d4f993f025269", "span_id": "b508654e4f5a1074", "http_method": "POST", "http_path": "/api/v1/packs/1918f298-14ba-4716-be25-64ddbb5f40cb/approve", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 412, "duration_ms": 5.671, "client_addr": "127.0.0.1"}
```

## Proof M4 — FAILURE (2026-07-01T09:10:26Z)

- Failed step: `BAR 1.4 approve (HTTP 412; body: {"detail":{"pack_kind":"tool","gates":[{"gate":"signature","outcome":"red","red_reason":"signature_bundle_path_unreachable","evidence_pointer":null},{"gate":"evaluation","outcome":"evidence_not_attached","red_reason":"evaluation_evidence_not_attached","evidence_pointer":null},{"gate":"adversarial","outcome":"evidence_not_attached","red_reason":"adversarial_evidence_not_attached","evidence_pointer":null},{"gate":"owasp_conformance","outcome":"green","red_reason":null,"evidence_pointer":null},{"gate":"reviewer_acknowledgement","outcome":"green","red_reason":null,"evidence_pointer":null}],"all_green":false,"non_overridable_red_gates":["signature"],"override_refusal_reason":"non_overridable_red_gate"}})`
- last API response (HTTP 412):
```json
{"detail":{"pack_kind":"tool","gates":[{"gate":"signature","outcome":"red","red_reason":"signature_bundle_path_unreachable","evidence_pointer":null},{"gate":"evaluation","outcome":"evidence_not_attached","red_reason":"evaluation_evidence_not_attached","evidence_pointer":null},{"gate":"adversarial","outcome":"evidence_not_attached","red_reason":"adversarial_evidence_not_attached","evidence_pointer":null},{"gate":"owasp_conformance","outcome":"green","red_reason":null,"evidence_pointer":null},{"gate":"reviewer_acknowledgement","outcome":"green","red_reason":null,"evidence_pointer":null}],"all_green":false,"non_overridable_red_gates":["signature"],"override_refusal_reason":"non_overridable_red_gate"}}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T09:10:20.357341+00:00","discovery_status":"unprobed"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":1,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
<none>
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 09:10:19,994", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 09:10:20,389", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 09:10:20,805", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0ae35cbcf35e4486895695447bbe8b15", "trace_id": "e3f7c4fa4d3db0475ec7281948a96d90", "span_id": "bf8e878773581aaa", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.95, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:10:21,328", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4e092cb5fdcc43e1a27f0b8d00e4157e", "trace_id": "36a6f9818a1142aa0480737fa43f34a8", "span_id": "5ef3a6b55c716cb3"}
{"ts": "2026-07-01 09:10:21,337", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4e092cb5fdcc43e1a27f0b8d00e4157e", "trace_id": "36a6f9818a1142aa0480737fa43f34a8", "span_id": "5ef3a6b55c716cb3"}
{"ts": "2026-07-01 09:10:21,346", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4e092cb5fdcc43e1a27f0b8d00e4157e", "trace_id": "36a6f9818a1142aa0480737fa43f34a8", "span_id": "5ef3a6b55c716cb3"}
{"ts": "2026-07-01 09:10:21,346", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4e092cb5fdcc43e1a27f0b8d00e4157e", "trace_id": "36a6f9818a1142aa0480737fa43f34a8", "span_id": "5ef3a6b55c716cb3", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.74, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:10:25,978", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e3a4067660c044da80d010eec02ac267", "trace_id": "55207abe07a556138183891fb35c0abc", "span_id": "c556bc29ddcf5688", "http_method": "POST", "http_path": "/api/v1/packs/drafts", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 28.201, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:10:26,066", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2d27d84ac6ff4a9ab289500f9ae6a51f", "trace_id": "5f54776ea116cf7c64e037e13296b4a7", "span_id": "3f199d29799f518b", "http_method": "POST", "http_path": "/api/v1/packs/drafts/b14af05a-4b8c-46be-9f80-37156b371c40/submit", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 11.578, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:10:26,091", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-636b4ddec01a4386a2bff0adcce03a81", "trace_id": "78e2d7f3fa643b7baf247de8c684300a", "span_id": "1acf956145b56868", "http_method": "POST", "http_path": "/api/v1/packs/b14af05a-4b8c-46be-9f80-37156b371c40/claim", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 5.814, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:10:26,141", "level": "WARNING", "logger": "cognic_agentos.portal.api.packs.review_routes", "message": "portal.packs.approve_override_refused", "request_id": "portal-req-23272d83033841a2b6055041ef778ca6", "trace_id": "c480aad9ee542e0d6ad6151737fd1a46", "span_id": "79cff8dff2111a2c", "reason": "non_overridable_red_gate", "actor_subject": "proof-m4-reviewer", "pack_id": "b14af05a-4b8c-46be-9f80-37156b371c40"}
{"ts": "2026-07-01 09:10:26,142", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-23272d83033841a2b6055041ef778ca6", "trace_id": "c480aad9ee542e0d6ad6151737fd1a46", "span_id": "79cff8dff2111a2c", "http_method": "POST", "http_path": "/api/v1/packs/b14af05a-4b8c-46be-9f80-37156b371c40/approve", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 412, "duration_ms": 5.632, "client_addr": "127.0.0.1"}
```

## Proof M4 — FAILURE (2026-07-01T09:28:48Z)

- Failed step: `BAR 1.4 approve (HTTP 412; body: {"detail":{"pack_kind":"tool","gates":[{"gate":"signature","outcome":"red","red_reason":"signature_cosign_verify_failed","evidence_pointer":null},{"gate":"evaluation","outcome":"evidence_not_attached","red_reason":"evaluation_evidence_not_attached","evidence_pointer":null},{"gate":"adversarial","outcome":"evidence_not_attached","red_reason":"adversarial_evidence_not_attached","evidence_pointer":null},{"gate":"owasp_conformance","outcome":"green","red_reason":null,"evidence_pointer":null},{"gate":"reviewer_acknowledgement","outcome":"green","red_reason":null,"evidence_pointer":null}],"all_green":false,"non_overridable_red_gates":["signature"],"override_refusal_reason":"non_overridable_red_gate"}})`
- last API response (HTTP 412):
```json
{"detail":{"pack_kind":"tool","gates":[{"gate":"signature","outcome":"red","red_reason":"signature_cosign_verify_failed","evidence_pointer":null},{"gate":"evaluation","outcome":"evidence_not_attached","red_reason":"evaluation_evidence_not_attached","evidence_pointer":null},{"gate":"adversarial","outcome":"evidence_not_attached","red_reason":"adversarial_evidence_not_attached","evidence_pointer":null},{"gate":"owasp_conformance","outcome":"green","red_reason":null,"evidence_pointer":null},{"gate":"reviewer_acknowledgement","outcome":"green","red_reason":null,"evidence_pointer":null}],"all_green":false,"non_overridable_red_gates":["signature"],"override_refusal_reason":"non_overridable_red_gate"}}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T09:28:38.349465+00:00","discovery_status":"unprobed"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":1,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
<none>
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 09:28:37,881", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 09:28:38,389", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 09:28:42,761", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9787c2d3be694adbbfea8d9b04097eb4", "trace_id": "17d62857dc09644413c423ec6bd11554", "span_id": "cf477272dc5c440d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.148, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:28:43,249", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-af95d774ee4d43dc89347d20b3c6c8e7", "trace_id": "cdde17e6b6a5f9895cf83e6faa68cb15", "span_id": "c7b585727163548f"}
{"ts": "2026-07-01 09:28:43,259", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-af95d774ee4d43dc89347d20b3c6c8e7", "trace_id": "cdde17e6b6a5f9895cf83e6faa68cb15", "span_id": "c7b585727163548f"}
{"ts": "2026-07-01 09:28:43,270", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-af95d774ee4d43dc89347d20b3c6c8e7", "trace_id": "cdde17e6b6a5f9895cf83e6faa68cb15", "span_id": "c7b585727163548f"}
{"ts": "2026-07-01 09:28:43,270", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-af95d774ee4d43dc89347d20b3c6c8e7", "trace_id": "cdde17e6b6a5f9895cf83e6faa68cb15", "span_id": "c7b585727163548f", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.803, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:28:47,758", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-70265026fa2e4856b1e280df350280de", "trace_id": "a908aa4e8d2033139ee1f4ea04d45f53", "span_id": "17d64d5e4b5f85b9", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.306, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 09:28:47,944", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3585b4debf91411cac57d773cf090553", "trace_id": "028585327befeadebe57f4253c2f2e98", "span_id": "6e4d69dd5d972627", "http_method": "POST", "http_path": "/api/v1/packs/drafts", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 31.255, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:28:48,049", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f364a1d7a0fc47569d4b68c19ade31a5", "trace_id": "4e6e6502140fafb3af4dbf821cc1ff7f", "span_id": "51379036d0e05b7f", "http_method": "POST", "http_path": "/api/v1/packs/drafts/bd1ef061-94ce-4e73-ae41-13a12063eb72/submit", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 13.477, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:28:48,077", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-11949c92cba04d0fb055de56625f4e10", "trace_id": "a4e84dec397a7533b31560042b957ce5", "span_id": "e4524098876fa530", "http_method": "POST", "http_path": "/api/v1/packs/bd1ef061-94ce-4e73-ae41-13a12063eb72/claim", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 7.551, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 09:28:48,382", "level": "WARNING", "logger": "cognic_agentos.portal.api.packs.review_routes", "message": "portal.packs.approve_override_refused", "request_id": "portal-req-1f4c954cdc0249409106f355082549d9", "trace_id": "8fbc8da1a53acb71931ce29dcffa60a6", "span_id": "d0c464fe4dd84f63", "reason": "non_overridable_red_gate", "actor_subject": "proof-m4-reviewer", "pack_id": "bd1ef061-94ce-4e73-ae41-13a12063eb72"}
{"ts": "2026-07-01 09:28:48,383", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1f4c954cdc0249409106f355082549d9", "trace_id": "8fbc8da1a53acb71931ce29dcffa60a6", "span_id": "d0c464fe4dd84f63", "http_method": "POST", "http_path": "/api/v1/packs/bd1ef061-94ce-4e73-ae41-13a12063eb72/approve", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 412, "duration_ms": 251.466, "client_addr": "127.0.0.1"}
```

## Proof M4 — FAILURE (2026-07-01T10:31:24Z)

- Failed step: `BAR 1.9 discovery_status=unprobed (expected auth_ready)`
- last API response (HTTP 200):
```json
{"id":"b3044530-776e-44b3-828c-c35cd9e08a8d","kind":"tool","pack_id":"cognic-tool-oracle-schema","display_name":"Cognic Oracle Schema (proof-m4)","state":"installed","tenant_id":"proof-m4","created_by":"proof-m4-author","last_actor":"proof-m4-operator","created_at":"2026-07-01T10:31:11.317937Z","updated_at":"2026-07-01T10:31:11.920028Z"}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T10:31:18.066289+00:00","discovery_status":"unprobed"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":1,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
mcp.runtime_config.activation|{"actor_type": "human", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "previous_status": "configured", "status": "active", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
mcp.override.set|{"actor_type": "human", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "previous_server_url": null, "server_url": "http://10.96.0.51:8765/mcp", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
mcp.allowlist.add|{"actor_type": "human", "ip": "10.96.0.51", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
pack.lifecycle.installed|{"actor_type": "human", "evidence_pointer": null, "from_state": "allow_listed", "iso_controls": ["A.5.31", "A.5.32"], "kind": "tool", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "to_state": "installed", "transition_name": "install", "actor_id": "proof-m4-operator"}
mcp.runtime_config.set|{"activation_status": "configured", "actor_type": "human", "as_allowlist_ref": "secret/cognic/proof-m4/mcp-as-allowlist", "generation": 1, "internal_host_allowlist": ["10.96.0.51"], "oauth_credential_ref": "secret/cognic/proof-m4/mcp-oauth/192.88.99.9_9000", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "server_url_override": "http://10.96.0.51:8765/mcp", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
pack.lifecycle.allow_listed|{"actor_type": "human", "evidence_pointer": null, "from_state": "approved", "iso_controls": ["A.5.31", "A.5.32"], "kind": "tool", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "to_state": "allow_listed", "transition_name": "allow_list", "actor_id": "proof-m4-operator"}
pack.lifecycle.approved|{"evidence_pointer": null, "from_state": "under_review", "iso_controls": ["A.5.31", "A.6.2.4"], "kind": "tool", "override_event_id": "f1266bf9-17a2-4d94-85b4-14e59ec604a3", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "reviewer_acknowledgement": {"conformance_acknowledged": true, "data_governance_acknowledged": true, "risk_tier_acknowledged": true, "supply_chain_acknowledged": true}, "to_state": "approved", "transition_name": "approve", "actor_id": "proof-m4-reviewer"}
pack.lifecycle.under_review|{"evidence_pointer": null, "from_state": "submitted", "iso_controls": ["A.5.31"], "kind": "tool", "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "to_state": "under_review", "transition_name": "claim", "actor_id": "proof-m4-reviewer"}
pack.lifecycle.submitted|{"conformance": {"errored_categories": [], "overall_status": "green", "results": {"dependency_poisoning": {"category": "dependency_poisoning", "findings": ["no [dependencies] declared"], "status": "not_applicable"}, "goal_hijacking": {"category": "goal_hijacking", "findings": ["manifest.pack.kind: check 'goal_hijacking' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "identity_abuse": {"category": "identity_abuse", "findings": [], "status": "pass"}, "prompt_injected_skills": {"category": "prompt_injected_skills", "findings": ["manifest.pack.kind: check 'prompt_injected_skills' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "secret_exfiltration": {"category": "secret_exfiltration", "findings": ["no [data_governance] block declared"], "status": "not_applicable"}, "skills_top_10": {"category": "skills_top_10", "findings": ["manifest.pack.kind: check 'skills_top_10' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "supply_chain_integrity": {"category": "supply_chain_integrity", "findings": [], "status": "pass"}, "tool_misuse": {"category": "tool_misuse", "findings": [], "status": "pass"}, "unsafe_filesystem": {"category": "unsafe_filesystem", "findings": [], "status": "pass"}, "unsafe_network": {"category": "unsafe_network", "findings": [], "status": "pass"}}, "summary": "5 pass / 0 fail / 5 not_applicable"}, "evidence_pointer": null, "from_state": "draft", "iso_controls": ["A.5.31", "A.6.2.4"], "kind": "tool", "manifest": {"identity": {"agent_id": "cognic-tool-oracle-schema", "display_name": "Cognic Oracle Schema (proof-m4)", "provider_organization": "Cognic", "provider_url": "https://cognic.example"}, "mcp": {"scopes": ["oracle_schema.read"], "server_url": "http://10.96.0.51:8765/mcp"}, "pack": {"kind": "tool", "name": "cognic-tool-oracle-schema", "version": "0.1.0"}, "risk_tier": {"tier": "read_only"}, "supply_chain": {"attestation_paths": ["cosign.sig", "bundle.sigstore", "sbom.cdx.json", "slsa-provenance.intoto.json", "intoto-layout.json", "vuln-scan.json", "license-audit.json"], "blob_path": "cognic_tool_oracle_schema-0.1.0-py3-none-any.whl"}}, "pack_id": "b3044530-776e-44b3-828c-c35cd9e08a8d", "signed_artefact_root": "/opt/cognic/pack-attestations/cognic-tool-oracle-schema/0.1.0", "to_state": "submitted", "transition_name": "submit", "actor_id": "proof-m4-author"}
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 10:31:17,616", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 10:31:18,103", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 10:31:22,418", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-538fad85eb464991aa70ed269226f4ed", "trace_id": "29e572b2c62f7aca45eb0ff3502e3d93", "span_id": "e1a2b7fea6d60aa8", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.296, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 10:31:22,647", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-359a835206584242989f85d120e08f8c", "trace_id": "621c3280ebce1614e4adddf1930b8aa8", "span_id": "0f7291c41fa289a9"}
{"ts": "2026-07-01 10:31:22,659", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-359a835206584242989f85d120e08f8c", "trace_id": "621c3280ebce1614e4adddf1930b8aa8", "span_id": "0f7291c41fa289a9"}
{"ts": "2026-07-01 10:31:22,669", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-359a835206584242989f85d120e08f8c", "trace_id": "621c3280ebce1614e4adddf1930b8aa8", "span_id": "0f7291c41fa289a9"}
{"ts": "2026-07-01 10:31:22,669", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-359a835206584242989f85d120e08f8c", "trace_id": "621c3280ebce1614e4adddf1930b8aa8", "span_id": "0f7291c41fa289a9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 30.664, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 10:31:24,016", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a7756db234b046aa9b3051415c1e038a", "trace_id": "2fe0fd4f10065192bec359b2d98dd68e", "span_id": "21f17608ee0e7a23", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.121, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 10:31:24,042", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2eb3e850bfe64d32948a6522953e5d6e", "trace_id": "ab515ed758c6108f30b69c625d24fb9d", "span_id": "4db31eeec2ffbf9e", "http_method": "GET", "http_path": "/api/v1/system/plugins", "http_has_query": true, "http_query_param_count": 1, "http_status_code": 200, "duration_ms": 0.948, "client_addr": "127.0.0.1"}
```

## Proof M4 — FAILURE (2026-07-01T10:42:18Z)

- Failed step: `BAR 1.10 list_tools (HTTP 502)`
- last API response (HTTP 502):
```json
{"detail":{"reason":"mcp_discovery_url_refused"}}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T10:42:12.735263+00:00","discovery_status":"refused"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":0,"auth_ready":0,"refused":1,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
mcp.runtime_config.activation|{"actor_type": "human", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "previous_status": "configured", "status": "active", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
mcp.override.set|{"actor_type": "human", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "previous_server_url": null, "server_url": "http://10.96.0.51:8765/mcp", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
mcp.allowlist.add|{"actor_type": "human", "ip": "10.96.0.51", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
pack.lifecycle.installed|{"actor_type": "human", "evidence_pointer": null, "from_state": "allow_listed", "iso_controls": ["A.5.31", "A.5.32"], "kind": "tool", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "to_state": "installed", "transition_name": "install", "actor_id": "proof-m4-operator"}
mcp.runtime_config.set|{"activation_status": "configured", "actor_type": "human", "as_allowlist_ref": "secret/cognic/proof-m4/mcp-as-allowlist", "generation": 1, "internal_host_allowlist": ["10.96.0.51"], "oauth_credential_ref": "secret/cognic/proof-m4/mcp-oauth/192.88.99.9_9000", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "server_url_override": "http://10.96.0.51:8765/mcp", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
pack.lifecycle.allow_listed|{"actor_type": "human", "evidence_pointer": null, "from_state": "approved", "iso_controls": ["A.5.31", "A.5.32"], "kind": "tool", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "to_state": "allow_listed", "transition_name": "allow_list", "actor_id": "proof-m4-operator"}
pack.lifecycle.approved|{"evidence_pointer": null, "from_state": "under_review", "iso_controls": ["A.5.31", "A.6.2.4"], "kind": "tool", "override_event_id": "3cff8c67-8145-447b-825e-930d2465919b", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "reviewer_acknowledgement": {"conformance_acknowledged": true, "data_governance_acknowledged": true, "risk_tier_acknowledged": true, "supply_chain_acknowledged": true}, "to_state": "approved", "transition_name": "approve", "actor_id": "proof-m4-reviewer"}
pack.lifecycle.under_review|{"evidence_pointer": null, "from_state": "submitted", "iso_controls": ["A.5.31"], "kind": "tool", "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "to_state": "under_review", "transition_name": "claim", "actor_id": "proof-m4-reviewer"}
pack.lifecycle.submitted|{"conformance": {"errored_categories": [], "overall_status": "green", "results": {"dependency_poisoning": {"category": "dependency_poisoning", "findings": ["no [dependencies] declared"], "status": "not_applicable"}, "goal_hijacking": {"category": "goal_hijacking", "findings": ["manifest.pack.kind: check 'goal_hijacking' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "identity_abuse": {"category": "identity_abuse", "findings": [], "status": "pass"}, "prompt_injected_skills": {"category": "prompt_injected_skills", "findings": ["manifest.pack.kind: check 'prompt_injected_skills' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "secret_exfiltration": {"category": "secret_exfiltration", "findings": ["no [data_governance] block declared"], "status": "not_applicable"}, "skills_top_10": {"category": "skills_top_10", "findings": ["manifest.pack.kind: check 'skills_top_10' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "supply_chain_integrity": {"category": "supply_chain_integrity", "findings": [], "status": "pass"}, "tool_misuse": {"category": "tool_misuse", "findings": [], "status": "pass"}, "unsafe_filesystem": {"category": "unsafe_filesystem", "findings": [], "status": "pass"}, "unsafe_network": {"category": "unsafe_network", "findings": [], "status": "pass"}}, "summary": "5 pass / 0 fail / 5 not_applicable"}, "evidence_pointer": null, "from_state": "draft", "iso_controls": ["A.5.31", "A.6.2.4"], "kind": "tool", "manifest": {"identity": {"agent_id": "cognic-tool-oracle-schema", "display_name": "Cognic Oracle Schema (proof-m4)", "provider_organization": "Cognic", "provider_url": "https://cognic.example"}, "mcp": {"scopes": ["oracle_schema.read"], "server_url": "http://10.96.0.51:8765/mcp"}, "pack": {"kind": "tool", "name": "cognic-tool-oracle-schema", "version": "0.1.0"}, "risk_tier": {"tier": "read_only"}, "supply_chain": {"attestation_paths": ["cosign.sig", "bundle.sigstore", "sbom.cdx.json", "slsa-provenance.intoto.json", "intoto-layout.json", "vuln-scan.json", "license-audit.json"], "blob_path": "cognic_tool_oracle_schema-0.1.0-py3-none-any.whl"}}, "pack_id": "62becea7-ebd6-4357-a526-0e5693d4cafd", "signed_artefact_root": "/opt/cognic/pack-attestations/cognic-tool-oracle-schema/0.1.0", "to_state": "submitted", "transition_name": "submit", "actor_id": "proof-m4-author"}
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 10:42:12,277", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 10:42:12,774", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 10:42:17,152", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-85e2221db71d436c85efd197a63a8bda", "trace_id": "60913362db50f76f014703ebd28c0e06", "span_id": "97f8e68128207123", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.021, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 10:42:17,286", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-222419eb74034b05ad2c5a18ba8adcf9", "trace_id": "0b44eefd038f5d4e4efae8b5ded80ad4", "span_id": "e2ba0675bd85576f"}
{"ts": "2026-07-01 10:42:17,296", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-222419eb74034b05ad2c5a18ba8adcf9", "trace_id": "0b44eefd038f5d4e4efae8b5ded80ad4", "span_id": "e2ba0675bd85576f"}
{"ts": "2026-07-01 10:42:17,306", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-222419eb74034b05ad2c5a18ba8adcf9", "trace_id": "0b44eefd038f5d4e4efae8b5ded80ad4", "span_id": "e2ba0675bd85576f"}
{"ts": "2026-07-01 10:42:17,306", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-222419eb74034b05ad2c5a18ba8adcf9", "trace_id": "0b44eefd038f5d4e4efae8b5ded80ad4", "span_id": "e2ba0675bd85576f", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.261, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 10:42:18,645", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-81a7f6841bea4fb7b3a1746250d92ba7", "trace_id": "ea9af071f4c077b0ad9bfb04c023fa1f", "span_id": "90db89e7056d3496", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.212, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 10:42:18,676", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-afa7edb4dd9845f9a1f067ef1e0b8557", "trace_id": "abc256f320585f190d9d694012d823f2", "span_id": "1c441364724f349e", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-oracle-schema/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 502, "duration_ms": 7.152, "client_addr": "127.0.0.1"}
```

## Proof M4 — FAILURE (2026-07-01T11:00:07Z)

- Failed step: `BAR 1.10 list_tools (HTTP 502)`
- last API response (HTTP 502):
```json
{"detail":{"reason":"mcp_discovery_url_refused"}}
```
- refusal / discovery reason markers:
```
<none captured>
```
- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-m4):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fa964ea0461cc824f5569bce41b8ee30449dca061e77699cee892a60f8d52c03","refusal_reason":null,"registered_at":"2026-07-01T11:00:00.779225+00:00","discovery_status":"refused"}],"summary":{"total_discovered":1,"registered":1,"refused_at_registration":0,"by_grade":{"full":0,"partial":1},"by_discovery_status":{"unprobed":0,"auth_ready":0,"refused":1,"unreachable":0}}}
```
- decision_history (mcp.* / pack.lifecycle.* tail 20):
```
mcp.runtime_config.activation|{"actor_type": "human", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "previous_status": "configured", "status": "active", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
mcp.override.set|{"actor_type": "human", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "previous_server_url": null, "server_url": "http://10.96.0.51:8765/mcp", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
mcp.allowlist.add|{"actor_type": "human", "ip": "10.96.0.51", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
pack.lifecycle.installed|{"actor_type": "human", "evidence_pointer": null, "from_state": "allow_listed", "iso_controls": ["A.5.31", "A.5.32"], "kind": "tool", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "to_state": "installed", "transition_name": "install", "actor_id": "proof-m4-operator"}
mcp.runtime_config.set|{"activation_status": "configured", "actor_type": "human", "as_allowlist_ref": "secret/cognic/proof-m4/mcp-as-allowlist", "generation": 1, "internal_host_allowlist": ["10.96.0.51"], "oauth_credential_ref": "secret/cognic/proof-m4/mcp-oauth/192.88.99.9_9000", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "server_url_override": "http://10.96.0.51:8765/mcp", "tenant_id": "proof-m4", "actor_id": "proof-m4-operator"}
pack.lifecycle.allow_listed|{"actor_type": "human", "evidence_pointer": null, "from_state": "approved", "iso_controls": ["A.5.31", "A.5.32"], "kind": "tool", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "to_state": "allow_listed", "transition_name": "allow_list", "actor_id": "proof-m4-operator"}
pack.lifecycle.approved|{"evidence_pointer": null, "from_state": "under_review", "iso_controls": ["A.5.31", "A.6.2.4"], "kind": "tool", "override_event_id": "e1840708-e20a-4a4d-bb8f-2b58eb6dd7c4", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "reviewer_acknowledgement": {"conformance_acknowledged": true, "data_governance_acknowledged": true, "risk_tier_acknowledged": true, "supply_chain_acknowledged": true}, "to_state": "approved", "transition_name": "approve", "actor_id": "proof-m4-reviewer"}
pack.lifecycle.under_review|{"evidence_pointer": null, "from_state": "submitted", "iso_controls": ["A.5.31"], "kind": "tool", "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "to_state": "under_review", "transition_name": "claim", "actor_id": "proof-m4-reviewer"}
pack.lifecycle.submitted|{"conformance": {"errored_categories": [], "overall_status": "green", "results": {"dependency_poisoning": {"category": "dependency_poisoning", "findings": ["no [dependencies] declared"], "status": "not_applicable"}, "goal_hijacking": {"category": "goal_hijacking", "findings": ["manifest.pack.kind: check 'goal_hijacking' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "identity_abuse": {"category": "identity_abuse", "findings": [], "status": "pass"}, "prompt_injected_skills": {"category": "prompt_injected_skills", "findings": ["manifest.pack.kind: check 'prompt_injected_skills' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "secret_exfiltration": {"category": "secret_exfiltration", "findings": ["no [data_governance] block declared"], "status": "not_applicable"}, "skills_top_10": {"category": "skills_top_10", "findings": ["manifest.pack.kind: check 'skills_top_10' does not apply to pack kind 'tool'"], "status": "not_applicable"}, "supply_chain_integrity": {"category": "supply_chain_integrity", "findings": [], "status": "pass"}, "tool_misuse": {"category": "tool_misuse", "findings": [], "status": "pass"}, "unsafe_filesystem": {"category": "unsafe_filesystem", "findings": [], "status": "pass"}, "unsafe_network": {"category": "unsafe_network", "findings": [], "status": "pass"}}, "summary": "5 pass / 0 fail / 5 not_applicable"}, "evidence_pointer": null, "from_state": "draft", "iso_controls": ["A.5.31", "A.6.2.4"], "kind": "tool", "manifest": {"identity": {"agent_id": "cognic-tool-oracle-schema", "display_name": "Cognic Oracle Schema (proof-m4)", "provider_organization": "Cognic", "provider_url": "https://cognic.example"}, "mcp": {"scopes": ["oracle_schema.read"], "server_url": "http://10.96.0.51:8765/mcp"}, "pack": {"kind": "tool", "name": "cognic-tool-oracle-schema", "version": "0.1.0"}, "risk_tier": {"tier": "read_only"}, "supply_chain": {"attestation_paths": ["cosign.sig", "bundle.sigstore", "sbom.cdx.json", "slsa-provenance.intoto.json", "intoto-layout.json", "vuln-scan.json", "license-audit.json"], "blob_path": "cognic_tool_oracle_schema-0.1.0-py3-none-any.whl"}}, "pack_id": "e043f1ed-a819-4334-9009-8196958dff58", "signed_artefact_root": "/opt/cognic/pack-attestations/cognic-tool-oracle-schema/0.1.0", "to_state": "submitted", "transition_name": "submit", "actor_id": "proof-m4-author"}
```
- derived MCP config rows (override + allow-list):
```
allowlist|proof-m4|10.96.0.51|proof-m4-operator
override|proof-m4|e043f1ed-a819-4334-9009-8196958dff58|http://10.96.0.51:8765/mcp
```
- audit.mcp_allowlist_permitted tail:
```
<none>
```
- AgentOS pod logs (tail 150):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-01 11:00:00,331", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-01 11:00:00,818", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
{"ts": "2026-07-01 11:00:05,152", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-47957ddcbc994b1ea576692ddb1aa3ad", "trace_id": "651e02122d2602b4350207051468c821", "span_id": "310511235789b01b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.0, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 11:00:05,288", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c21a3b917228420e974c5b6970fc3f98", "trace_id": "75e5ad76bf29bff824b9902c96304f3a", "span_id": "6883219e9494962c"}
{"ts": "2026-07-01 11:00:05,298", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c21a3b917228420e974c5b6970fc3f98", "trace_id": "75e5ad76bf29bff824b9902c96304f3a", "span_id": "6883219e9494962c"}
{"ts": "2026-07-01 11:00:05,308", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c21a3b917228420e974c5b6970fc3f98", "trace_id": "75e5ad76bf29bff824b9902c96304f3a", "span_id": "6883219e9494962c"}
{"ts": "2026-07-01 11:00:05,308", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c21a3b917228420e974c5b6970fc3f98", "trace_id": "75e5ad76bf29bff824b9902c96304f3a", "span_id": "6883219e9494962c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.553, "client_addr": "10.244.0.1"}
{"ts": "2026-07-01 11:00:06,650", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b5397250cd604c79ac304e3dfad129c5", "trace_id": "2cb769ce31f2a81462e769f25f11d9fa", "span_id": "d59c800148ff9464", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.171, "client_addr": "127.0.0.1"}
{"ts": "2026-07-01 11:00:06,682", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8f078e3c22a24df58910c176dc3d3570", "trace_id": "469d51c8c88817608dbdcfe7bef165f5", "span_id": "8dfe3e4302b99834", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-oracle-schema/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 502, "duration_ms": 6.503, "client_addr": "127.0.0.1"}
```

## Proof M4 — AgentOS rollout FAILURE (2026-07-01T12:24:16Z)

- Failed step: `rel-agentos rollout did not complete within 600s`
- rel-agentos deploy/pods (-o wide):
```
error: selectors and the all flag cannot be used when passing resource/name arguments
```
- rel-agentos deployment describe:
```
Name:                   rel-agentos
Namespace:              cognic-proofm4
CreationTimestamp:      Wed, 01 Jul 2026 17:09:26 +0500
Labels:                 app.kubernetes.io/instance=rel
                        app.kubernetes.io/managed-by=Helm
                        app.kubernetes.io/name=agentos
                        app.kubernetes.io/part-of=cognic-agentos
                        helm.sh/chart=agentos-0.1.0
Annotations:            deployment.kubernetes.io/revision: 2
                        meta.helm.sh/release-name: rel
                        meta.helm.sh/release-namespace: cognic-proofm4
Selector:               app.kubernetes.io/instance=rel,app.kubernetes.io/name=agentos
Replicas:               1 desired | 1 updated | 2 total | 0 available | 2 unavailable
StrategyType:           RollingUpdate
MinReadySeconds:        0
RollingUpdateStrategy:  25% max unavailable, 25% max surge
Pod Template:
  Labels:           app.kubernetes.io/instance=rel
                    app.kubernetes.io/name=agentos
  Annotations:      kubectl.kubernetes.io/restartedAt: 2026-07-01T17:09:32+05:00
  Service Account:  rel-agentos
  Containers:
   agentos:
    Image:           cognic-agentos:proofm4
    Port:            8000/TCP
    Host Port:       0/TCP
    SeccompProfile:  RuntimeDefault
    Limits:
      cpu:     2
      memory:  2Gi
    Requests:
      cpu:      250m
      memory:   512Mi
    Liveness:   http-get http://:http/api/v1/healthz delay=0s timeout=5s period=15s #success=1 #failure=3
    Readiness:  http-get http://:http/api/v1/readyz delay=0s timeout=5s period=10s #success=1 #failure=3
    Startup:    http-get http://:http/api/v1/healthz delay=0s timeout=1s period=5s #success=1 #failure=30
    Environment Variables from:
      rel-agentos-config  ConfigMap  Optional: false
    Environment:
      COGNIC_PORT:          8000
      COGNIC_DATABASE_URL:  <set to the key 'COGNIC_DATABASE_URL' in secret 'rel-agentos-secrets'>  Optional: false
      COGNIC_VAULT_TOKEN:   <set to the key 'COGNIC_VAULT_TOKEN' in secret 'rel-agentos-secrets'>   Optional: false
    Mounts:
      /app/infra/litellm from litellm-config (ro)
      /tmp from tmp (rw)
      /var/lib/cognic-agentos/object-store from object-store (rw)
      /var/lib/cognic/model-artifacts from model-artifacts (rw)
  Volumes:
   litellm-config:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      rel-agentos-litellm
    Optional:  false
   tmp:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  256Mi
   object-store:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  5Gi
   model-artifacts:
    Type:          EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:     5Gi
  Node-Selectors:  <none>
  Tolerations:     <none>
Conditions:
  Type           Status  Reason
  ----           ------  ------
  Available      False   MinimumReplicasUnavailable
  Progressing    True    ReplicaSetUpdated
OldReplicaSets:  rel-agentos-5d87df78f4 (1/1 replicas created)
NewReplicaSet:   rel-agentos-f7bf6d56c (1/1 replicas created)
Events:
  Type    Reason             Age   From                   Message
  ----    ------             ----  ----                   -------
  Normal  ScalingReplicaSet  14m   deployment-controller  Scaled up replica set rel-agentos-5d87df78f4 from 0 to 1
  Normal  ScalingReplicaSet  14m   deployment-controller  Scaled up replica set rel-agentos-f7bf6d56c from 0 to 1
```
- rel-agentos pod describe:
```
Name:             rel-agentos-5d87df78f4-5wcbh
Namespace:        cognic-proofm4
Priority:         0
Service Account:  rel-agentos
Node:             cognic-proofm4-control-plane/172.27.0.2
Start Time:       Wed, 01 Jul 2026 17:09:26 +0500
Labels:           app.kubernetes.io/instance=rel
                  app.kubernetes.io/name=agentos
                  pod-template-hash=5d87df78f4
Annotations:      <none>
Status:           Running
IP:               10.244.0.12
IPs:
  IP:           10.244.0.12
Controlled By:  ReplicaSet/rel-agentos-5d87df78f4
Containers:
  agentos:
    Container ID:    containerd://5a7ec26486eb2ca05d4376351c726f89347acff0235c5df18331e707bd21aa83
    Image:           cognic-agentos:proofm4
    Image ID:        docker.io/library/import-2026-07-01@sha256:6685d2f407a91e1db37d3b893189e3323d41814e40ad5a2341d1995e2c658a14
    Port:            8000/TCP
    Host Port:       0/TCP
    SeccompProfile:  RuntimeDefault
    State:           Waiting
      Reason:        CrashLoopBackOff
    Last State:      Terminated
      Reason:        Error
      Exit Code:     1
      Started:       Wed, 01 Jul 2026 17:24:01 +0500
      Finished:      Wed, 01 Jul 2026 17:24:02 +0500
    Ready:           False
    Restart Count:   7
    Limits:
      cpu:     2
      memory:  2Gi
    Requests:
      cpu:      250m
      memory:   512Mi
    Liveness:   http-get http://:http/api/v1/healthz delay=0s timeout=5s period=15s #success=1 #failure=3
    Readiness:  http-get http://:http/api/v1/readyz delay=0s timeout=5s period=10s #success=1 #failure=3
    Startup:    http-get http://:http/api/v1/healthz delay=0s timeout=1s period=5s #success=1 #failure=30
    Environment Variables from:
      rel-agentos-config  ConfigMap  Optional: false
    Environment:
      COGNIC_PORT:          8000
      COGNIC_DATABASE_URL:  <set to the key 'COGNIC_DATABASE_URL' in secret 'rel-agentos-secrets'>  Optional: false
      COGNIC_VAULT_TOKEN:   <set to the key 'COGNIC_VAULT_TOKEN' in secret 'rel-agentos-secrets'>   Optional: false
    Mounts:
      /app/infra/litellm from litellm-config (ro)
      /tmp from tmp (rw)
      /var/lib/cognic-agentos/object-store from object-store (rw)
      /var/lib/cognic/model-artifacts from model-artifacts (rw)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True
  Initialized                 True
  Ready                       False
  ContainersReady             False
  PodScheduled                True
Volumes:
  litellm-config:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      rel-agentos-litellm
    Optional:  false
  tmp:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  256Mi
  object-store:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  5Gi
  model-artifacts:
    Type:        EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:   5Gi
QoS Class:       Burstable
Node-Selectors:  <none>
Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type     Reason     Age                   From               Message
  ----     ------     ----                  ----               -------
  Normal   Scheduled  14m                   default-scheduler  Successfully assigned cognic-proofm4/rel-agentos-5d87df78f4-5wcbh to cognic-proofm4-control-plane
  Warning  Unhealthy  11m (x2 over 14m)     kubelet            Startup probe failed: Get "http://10.244.0.12:8000/api/v1/healthz": dial tcp 10.244.0.12:8000: connect: connection refused
  Warning  BackOff    8m35s (x24 over 14m)  kubelet            Back-off restarting failed container agentos in pod rel-agentos-5d87df78f4-5wcbh_cognic-proofm4(90c4ffd9-f1bd-4935-8993-9b90c38cc74f)
  Normal   Pulled     15s (x8 over 14m)     kubelet            Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
  Normal   Created    15s (x8 over 14m)     kubelet            Container created
  Normal   Started    15s (x8 over 14m)     kubelet            Container started


Name:             rel-agentos-f7bf6d56c-q8wk4
Namespace:        cognic-proofm4
Priority:         0
Service Account:  rel-agentos
Node:             cognic-proofm4-control-plane/172.27.0.2
Start Time:       Wed, 01 Jul 2026 17:09:32 +0500
Labels:           app.kubernetes.io/instance=rel
                  app.kubernetes.io/name=agentos
                  pod-template-hash=f7bf6d56c
Annotations:      kubectl.kubernetes.io/restartedAt: 2026-07-01T17:09:32+05:00
Status:           Running
IP:               10.244.0.16
IPs:
  IP:           10.244.0.16
Controlled By:  ReplicaSet/rel-agentos-f7bf6d56c
Containers:
  agentos:
    Container ID:    containerd://9aade0cba2ea040a5291ef02f482098488e052a91ea2d5bd10a3486d1c4e4eb8
    Image:           cognic-agentos:proofm4
    Image ID:        docker.io/library/import-2026-07-01@sha256:6685d2f407a91e1db37d3b893189e3323d41814e40ad5a2341d1995e2c658a14
    Port:            8000/TCP
    Host Port:       0/TCP
    SeccompProfile:  RuntimeDefault
    State:           Waiting
      Reason:        CrashLoopBackOff
    Last State:      Terminated
      Reason:        Error
      Exit Code:     1
      Started:       Wed, 01 Jul 2026 17:15:10 +0500
      Finished:      Wed, 01 Jul 2026 17:15:11 +0500
    Ready:           False
    Restart Count:   6
    Limits:
      cpu:     2
      memory:  2Gi
    Requests:
      cpu:      250m
      memory:   512Mi
    Liveness:   http-get http://:http/api/v1/healthz delay=0s timeout=5s period=15s #success=1 #failure=3
    Readiness:  http-get http://:http/api/v1/readyz delay=0s timeout=5s period=10s #success=1 #failure=3
    Startup:    http-get http://:http/api/v1/healthz delay=0s timeout=1s period=5s #success=1 #failure=30
    Environment Variables from:
      rel-agentos-config  ConfigMap  Optional: false
    Environment:
      COGNIC_PORT:          8000
      COGNIC_DATABASE_URL:  <set to the key 'COGNIC_DATABASE_URL' in secret 'rel-agentos-secrets'>  Optional: false
      COGNIC_VAULT_TOKEN:   <set to the key 'COGNIC_VAULT_TOKEN' in secret 'rel-agentos-secrets'>   Optional: false
    Mounts:
      /app/infra/litellm from litellm-config (ro)
      /tmp from tmp (rw)
      /var/lib/cognic-agentos/object-store from object-store (rw)
      /var/lib/cognic/model-artifacts from model-artifacts (rw)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True
  Initialized                 True
  Ready                       False
  ContainersReady             False
  PodScheduled                True
Volumes:
  litellm-config:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      rel-agentos-litellm
    Optional:  false
  tmp:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  256Mi
  object-store:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  5Gi
  model-artifacts:
    Type:        EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:   5Gi
QoS Class:       Burstable
Node-Selectors:  <none>
Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type     Reason     Age                   From               Message
  ----     ------     ----                  ----               -------
  Normal   Scheduled  14m                   default-scheduler  Successfully assigned cognic-proofm4/rel-agentos-f7bf6d56c-q8wk4 to cognic-proofm4-control-plane
  Warning  Unhealthy  14m                   kubelet            Startup probe failed: Get "http://10.244.0.16:8000/api/v1/healthz": dial tcp 10.244.0.16:8000: connect: connection refused
  Normal   Pulled     9m6s (x7 over 14m)    kubelet            Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
  Normal   Created    9m6s (x7 over 14m)    kubelet            Container created
  Normal   Started    9m6s (x7 over 14m)    kubelet            Container started
  Warning  BackOff    4m49s (x22 over 14m)  kubelet            Back-off restarting failed container agentos in pod rel-agentos-f7bf6d56c-q8wk4_cognic-proofm4(2ecfe598-c091-4f3a-ab08-904bd295ed1d)
```
- rel-agentos logs (tail 220):
```
[pod/rel-agentos-5d87df78f4-5wcbh/agentos] Traceback (most recent call last):
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/bin/uvicorn", line 10, in <module>
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     sys.exit(main())
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]              ^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 1514, in __call__
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return self.main(*args, **kwargs)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 1435, in main
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     rv = self.invoke(ctx)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]          ^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 1298, in invoke
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return ctx.invoke(self.callback, **ctx.params)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 853, in invoke
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return callback(*args, **kwargs)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/main.py", line 441, in main
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     run(
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/main.py", line 617, in run
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     server.run()
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/server.py", line 75, in run
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return asyncio_run(self.serve(sockets=sockets), loop_factory=self.config.get_loop_factory())
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/usr/local/lib/python3.12/asyncio/runners.py", line 194, in run
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return runner.run(main)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/usr/local/lib/python3.12/asyncio/runners.py", line 118, in run
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return self._loop.run_until_complete(task)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "uvloop/loop.pyx", line 1518, in uvloop.loop.Loop.run_until_complete
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/server.py", line 79, in serve
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     await self._serve(sockets)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/server.py", line 86, in _serve
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     config.load()
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/config.py", line 449, in load
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     self.loaded_app = import_from_string(self.app)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/importer.py", line 19, in import_from_string
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     module = importlib.import_module(module_str)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/usr/local/lib/python3.12/importlib/__init__.py", line 90, in import_module
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     return _bootstrap._gcd_import(name[level:], package, level)
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 1387, in _gcd_import
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap_external>", line 999, in exec_module
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 488, in _call_with_frames_removed
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "/app/proof_m4/proof_app.py", line 52, in <module>
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]     from cognic_agentos.portal.rbac.actor import Actor
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap_external>", line 995, in exec_module
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap_external>", line 1132, in get_code
[pod/rel-agentos-5d87df78f4-5wcbh/agentos]   File "<frozen importlib._bootstrap_external>", line 1190, in get_data
[pod/rel-agentos-5d87df78f4-5wcbh/agentos] PermissionError: [Errno 13] Permission denied: '/opt/venv/lib/python3.12/site-packages/cognic_agentos/portal/rbac/actor.py'
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos] Traceback (most recent call last):
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/bin/uvicorn", line 10, in <module>
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     sys.exit(main())
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]              ^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 1514, in __call__
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return self.main(*args, **kwargs)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 1435, in main
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     rv = self.invoke(ctx)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]          ^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 1298, in invoke
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return ctx.invoke(self.callback, **ctx.params)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/click/core.py", line 853, in invoke
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return callback(*args, **kwargs)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/main.py", line 441, in main
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     run(
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/main.py", line 617, in run
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     server.run()
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/server.py", line 75, in run
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return asyncio_run(self.serve(sockets=sockets), loop_factory=self.config.get_loop_factory())
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/usr/local/lib/python3.12/asyncio/runners.py", line 194, in run
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return runner.run(main)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/usr/local/lib/python3.12/asyncio/runners.py", line 118, in run
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return self._loop.run_until_complete(task)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "uvloop/loop.pyx", line 1518, in uvloop.loop.Loop.run_until_complete
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/server.py", line 79, in serve
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     await self._serve(sockets)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/server.py", line 86, in _serve
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     config.load()
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/config.py", line 449, in load
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     self.loaded_app = import_from_string(self.app)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/opt/venv/lib/python3.12/site-packages/uvicorn/importer.py", line 19, in import_from_string
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     module = importlib.import_module(module_str)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/usr/local/lib/python3.12/importlib/__init__.py", line 90, in import_module
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     return _bootstrap._gcd_import(name[level:], package, level)
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 1387, in _gcd_import
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap_external>", line 999, in exec_module
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 488, in _call_with_frames_removed
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "/app/proof_m4/proof_app.py", line 52, in <module>
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]     from cognic_agentos.portal.rbac.actor import Actor
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 1360, in _find_and_load
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 1331, in _find_and_load_unlocked
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap>", line 935, in _load_unlocked
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap_external>", line 995, in exec_module
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap_external>", line 1132, in get_code
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos]   File "<frozen importlib._bootstrap_external>", line 1190, in get_data
[pod/rel-agentos-f7bf6d56c-q8wk4/agentos] PermissionError: [Errno 13] Permission denied: '/opt/venv/lib/python3.12/site-packages/cognic_agentos/portal/rbac/actor.py'
```
- namespace events (tail 160):
```
LAST SEEN   TYPE      REASON              OBJECT                                    MESSAGE
16m         Normal    SuccessfulCreate    replicaset/ollama-84dd449db5              Created pod: ollama-84dd449db5-qsfg9
16m         Normal    ScalingReplicaSet   deployment/qdrant                         Scaled up replica set qdrant-54644949b7 from 0 to 1
16m         Normal    SuccessfulCreate    replicaset/qdrant-54644949b7              Created pod: qdrant-54644949b7-mhgrg
16m         Normal    Scheduled           pod/qdrant-54644949b7-mhgrg               Successfully assigned cognic-proofm4/qdrant-54644949b7-mhgrg to cognic-proofm4-control-plane
16m         Normal    Scheduled           pod/vault-564b656fbf-lbvdv                Successfully assigned cognic-proofm4/vault-564b656fbf-lbvdv to cognic-proofm4-control-plane
16m         Normal    SuccessfulCreate    replicaset/vault-564b656fbf               Created pod: vault-564b656fbf-lbvdv
16m         Normal    Scheduled           pod/langfuse-77458bd486-jcjhd             Successfully assigned cognic-proofm4/langfuse-77458bd486-jcjhd to cognic-proofm4-control-plane
16m         Normal    SuccessfulCreate    replicaset/langfuse-77458bd486            Created pod: langfuse-77458bd486-jcjhd
16m         Normal    ScalingReplicaSet   deployment/langfuse                       Scaled up replica set langfuse-77458bd486 from 0 to 1
16m         Normal    Scheduled           pod/litellm-854bfdcb5d-vsp6c              Successfully assigned cognic-proofm4/litellm-854bfdcb5d-vsp6c to cognic-proofm4-control-plane
16m         Normal    ScalingReplicaSet   deployment/vault                          Scaled up replica set vault-564b656fbf from 0 to 1
16m         Normal    ScalingReplicaSet   deployment/postgres                       Scaled up replica set postgres-74b77c4f75 from 0 to 1
16m         Normal    SuccessfulCreate    replicaset/postgres-74b77c4f75            Created pod: postgres-74b77c4f75-dbf5m
16m         Normal    Scheduled           pod/postgres-74b77c4f75-dbf5m             Successfully assigned cognic-proofm4/postgres-74b77c4f75-dbf5m to cognic-proofm4-control-plane
16m         Normal    SuccessfulCreate    replicaset/litellm-854bfdcb5d             Created pod: litellm-854bfdcb5d-vsp6c
16m         Normal    ScalingReplicaSet   deployment/litellm                        Scaled up replica set litellm-854bfdcb5d from 0 to 1
16m         Normal    Scheduled           pod/ollama-84dd449db5-qsfg9               Successfully assigned cognic-proofm4/ollama-84dd449db5-qsfg9 to cognic-proofm4-control-plane
16m         Normal    ScalingReplicaSet   deployment/ollama                         Scaled up replica set ollama-84dd449db5 from 0 to 1
16m         Normal    Created             pod/postgres-74b77c4f75-dbf5m             Container created
16m         Normal    Pulled              pod/qdrant-54644949b7-mhgrg               Container image "qdrant/qdrant:v1.17.1" already present on machine and can be accessed by the pod
16m         Normal    Created             pod/ollama-84dd449db5-qsfg9               Container created
16m         Normal    Pulled              pod/ollama-84dd449db5-qsfg9               Container image "ollama/ollama:0.5.4" already present on machine and can be accessed by the pod
16m         Normal    Created             pod/vault-564b656fbf-lbvdv                Container created
16m         Normal    Pulled              pod/vault-564b656fbf-lbvdv                Container image "hashicorp/vault:1.18" already present on machine and can be accessed by the pod
16m         Normal    Pulled              pod/litellm-854bfdcb5d-vsp6c              Container image "ghcr.io/berriai/litellm:main-stable" already present on machine and can be accessed by the pod
16m         Normal    Started             pod/vault-564b656fbf-lbvdv                Container started
16m         Normal    Created             pod/qdrant-54644949b7-mhgrg               Container created
16m         Normal    Started             pod/qdrant-54644949b7-mhgrg               Container started
16m         Warning   Unhealthy           pod/qdrant-54644949b7-mhgrg               Readiness probe failed: Get "http://10.244.0.6:6333/readyz": dial tcp 10.244.0.6:6333: connect: connection refused
16m         Normal    Pulled              pod/postgres-74b77c4f75-dbf5m             Container image "postgres:16-alpine" already present on machine and can be accessed by the pod
16m         Normal    Started             pod/ollama-84dd449db5-qsfg9               Container started
16m         Normal    Started             pod/postgres-74b77c4f75-dbf5m             Container started
16m         Normal    Created             pod/litellm-854bfdcb5d-vsp6c              Container created
16m         Normal    Started             pod/litellm-854bfdcb5d-vsp6c              Container started
16m         Warning   Unhealthy           pod/vault-564b656fbf-lbvdv                Readiness probe failed: Get "http://10.244.0.7:8200/v1/sys/health": dial tcp 10.244.0.7:8200: connect: connection refused
16m         Warning   Unhealthy           pod/postgres-74b77c4f75-dbf5m             Readiness probe failed: /var/run/postgresql:5432 - no response
16m         Warning   BackOff             pod/langfuse-77458bd486-jcjhd             Back-off restarting failed container langfuse in pod langfuse-77458bd486-jcjhd_cognic-proofm4(adcfda9f-8d74-4c94-8080-4c3c75fedd7a)
16m         Warning   Unhealthy           pod/litellm-854bfdcb5d-vsp6c              Readiness probe failed: Get "http://10.244.0.10:4000/health/liveliness": dial tcp 10.244.0.10:4000: connect: connection refused
16m         Normal    Started             pod/langfuse-77458bd486-jcjhd             Container started
16m         Normal    Created             pod/langfuse-77458bd486-jcjhd             Container created
16m         Normal    Pulled              pod/langfuse-77458bd486-jcjhd             Container image "langfuse/langfuse:2" already present on machine and can be accessed by the pod
16m         Warning   Unhealthy           pod/langfuse-77458bd486-jcjhd             Readiness probe failed: Get "http://10.244.0.9:3000/api/public/health": dial tcp 10.244.0.9:3000: connect: connection refused
15m         Normal    SuccessfulCreate    replicaset/oracle-xe-6fbd6d88cc           Created pod: oracle-xe-6fbd6d88cc-7t7ch
15m         Normal    ScalingReplicaSet   deployment/oracle-xe                      Scaled up replica set oracle-xe-6fbd6d88cc from 0 to 1
15m         Normal    Scheduled           pod/oracle-xe-6fbd6d88cc-7t7ch            Successfully assigned cognic-proofm4/oracle-xe-6fbd6d88cc-7t7ch to cognic-proofm4-control-plane
15m         Normal    Started             pod/oracle-xe-6fbd6d88cc-7t7ch            Container started
15m         Normal    Created             pod/oracle-xe-6fbd6d88cc-7t7ch            Container created
15m         Normal    Pulled              pod/oracle-xe-6fbd6d88cc-7t7ch            Container image "gvenzl/oracle-xe:21-slim" already present on machine and can be accessed by the pod
14m         Normal    SuccessfulCreate    replicaset/rel-agentos-5d87df78f4         Created pod: rel-agentos-5d87df78f4-5wcbh
14m         Normal    Scheduled           pod/agentos-migrate-gqwrr                 Successfully assigned cognic-proofm4/agentos-migrate-gqwrr to cognic-proofm4-control-plane
14m         Normal    Scheduled           pod/rel-agentos-5d87df78f4-5wcbh          Successfully assigned cognic-proofm4/rel-agentos-5d87df78f4-5wcbh to cognic-proofm4-control-plane
14m         Normal    Pulled              pod/agentos-migrate-gqwrr                 Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
14m         Normal    ScalingReplicaSet   deployment/rel-agentos                    Scaled up replica set rel-agentos-5d87df78f4 from 0 to 1
14m         Normal    Created             pod/agentos-migrate-gqwrr                 Container created
14m         Normal    Started             pod/agentos-migrate-gqwrr                 Container started
14m         Normal    SuccessfulCreate    job/agentos-migrate                       Created pod: agentos-migrate-gqwrr
14m         Normal    Scheduled           pod/proof-as-6ccbcb589d-q8gkp             Successfully assigned cognic-proofm4/proof-as-6ccbcb589d-q8gkp to cognic-proofm4-control-plane
14m         Normal    Completed           job/agentos-migrate                       Job completed
14m         Normal    Scheduled           pod/proof-oracle-pack-8558fcb7c4-mk7lk    Successfully assigned cognic-proofm4/proof-oracle-pack-8558fcb7c4-mk7lk to cognic-proofm4-control-plane
14m         Normal    ScalingReplicaSet   deployment/proof-oracle-pack              Scaled up replica set proof-oracle-pack-8558fcb7c4 from 0 to 1
14m         Normal    SuccessfulCreate    replicaset/proof-oracle-pack-8558fcb7c4   Created pod: proof-oracle-pack-8558fcb7c4-mk7lk
14m         Normal    SuccessfulCreate    replicaset/proof-as-6ccbcb589d            Created pod: proof-as-6ccbcb589d-q8gkp
14m         Normal    ScalingReplicaSet   deployment/proof-as                       Scaled up replica set proof-as-6ccbcb589d from 0 to 1
14m         Normal    Created             pod/proof-as-6ccbcb589d-q8gkp             Container created
14m         Normal    Pulled              pod/proof-oracle-pack-8558fcb7c4-mk7lk    Container image "cognic-proof-oracle-pack:m4" already present on machine and can be accessed by the pod
14m         Normal    Pulled              pod/proof-as-6ccbcb589d-q8gkp             Container image "cognic-proof-as:m4" already present on machine and can be accessed by the pod
14m         Normal    Started             pod/proof-as-6ccbcb589d-q8gkp             Container started
14m         Normal    Pulled              pod/proof-oracle-pack-8558fcb7c4-mk7lk    Container image "busybox:1.36" already present on machine and can be accessed by the pod
14m         Normal    Created             pod/proof-oracle-pack-8558fcb7c4-mk7lk    Container created
14m         Normal    Scheduled           pod/rel-agentos-f7bf6d56c-q8wk4           Successfully assigned cognic-proofm4/rel-agentos-f7bf6d56c-q8wk4 to cognic-proofm4-control-plane
14m         Normal    Started             pod/proof-oracle-pack-8558fcb7c4-mk7lk    Container started
14m         Normal    Created             pod/proof-oracle-pack-8558fcb7c4-mk7lk    Container created
14m         Normal    ScalingReplicaSet   deployment/rel-agentos                    Scaled up replica set rel-agentos-f7bf6d56c from 0 to 1
14m         Normal    Started             pod/proof-oracle-pack-8558fcb7c4-mk7lk    Container started
14m         Normal    SuccessfulCreate    replicaset/rel-agentos-f7bf6d56c          Created pod: rel-agentos-f7bf6d56c-q8wk4
14m         Warning   Unhealthy           pod/rel-agentos-f7bf6d56c-q8wk4           Startup probe failed: Get "http://10.244.0.16:8000/api/v1/healthz": dial tcp 10.244.0.16:8000: connect: connection refused
11m         Warning   Unhealthy           pod/rel-agentos-5d87df78f4-5wcbh          Startup probe failed: Get "http://10.244.0.12:8000/api/v1/healthz": dial tcp 10.244.0.12:8000: connect: connection refused
9m6s        Normal    Started             pod/rel-agentos-f7bf6d56c-q8wk4           Container started
9m6s        Normal    Created             pod/rel-agentos-f7bf6d56c-q8wk4           Container created
9m6s        Normal    Pulled              pod/rel-agentos-f7bf6d56c-q8wk4           Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
8m35s       Warning   BackOff             pod/rel-agentos-5d87df78f4-5wcbh          Back-off restarting failed container agentos in pod rel-agentos-5d87df78f4-5wcbh_cognic-proofm4(90c4ffd9-f1bd-4935-8993-9b90c38cc74f)
4m49s       Warning   BackOff             pod/rel-agentos-f7bf6d56c-q8wk4           Back-off restarting failed container agentos in pod rel-agentos-f7bf6d56c-q8wk4_cognic-proofm4(2ecfe598-c091-4f3a-ab08-904bd295ed1d)
15s         Normal    Created             pod/rel-agentos-5d87df78f4-5wcbh          Container created
15s         Normal    Pulled              pod/rel-agentos-5d87df78f4-5wcbh          Container image "cognic-agentos:proofm4" already present on machine and can be accessed by the pod
15s         Normal    Started             pod/rel-agentos-5d87df78f4-5wcbh          Container started
```

## M4 — Operator-grade pack install flow — PASS

**2026-07-01 — M4 proven: the released signed `cognic-tool-oracle-schema@v0.1.0` pack became callable only through the real operator lifecycle path, and disable/revoke removed callability through the materialized MCP carve-outs.**

> M4 closes the gap left honest in M3: M3 proved a separate signed external pack can be boot-trusted and called through AgentOS, but the proof harness still seeded the override / internal-host allow-list / OAuth material directly. M4 drives the operator API lifecycle instead: submit -> review/approve -> allow-list -> configure -> install -> disable -> re-install -> revoke. The desired runtime-config record is authoritative; the derived MCP carve-out rows are materialized and retracted by the install/disable/revoke transitions.

### Run metadata
- **Date:** 2026-07-01 (operator-run, env-gated)
- **Command:** `COGNIC_RUN_PROOF_M4=1 COGNIC_PROOF_M4_REUSE_IMAGES=1 COGNIC_PROOF_M4_REBUILD_AGENTOS=1 bash infra/proof-m4/run-proof-m4.sh` -> **`RUNNER_EXIT=0`**
- **Run log:** preserved locally at `scratchpad/proof-m4-PASS-run22.log`; the durable pass markers are recorded below.
- **Released pack:** `cognic-tool-oracle-schema@v0.1.0`, downloaded from the public GitHub Release and staged with the previously verified wheel / `cosign.pub` digests from the M3 proof. The proof image used the released pack wheel; the AgentOS proof image was rebuilt with the current M4 branch source overlay so the unmerged operator-install implementation was exercised before PR.
- **Topology:** kind, Helm overlay `infra/proof-m4/`, the six bundled backends, in-cluster Oracle XE (`gvenzl/oracle-xe:21-slim`, built-in `XEPDB1`, seeded `COGNIC.*` schema), the released oracle MCP pack at ClusterIP `10.96.0.51`, and the proof RS256/JWKS AS at `192.88.99.9:9000`. Tenant `proof-m4`.
- **Actors:** distinct proof actors for author, reviewer, operator-human, and MCP caller. The reviewer is not the author; configure / install / disable / revoke are driven by an operator-human actor.

### Bar 1 (operator lifecycle happy path) — PASS
- **Bar 1.1-1.3:** author creates draft and submits; distinct reviewer claims.
- **Bar 1.4:** reviewer approves with the signature gate kept real-green; the four non-signature gates are overridden with an explicit `override_reason` for the proof.
- **Bar 1.5:** operator allow-lists the pack through the pack lifecycle API.
- **Bar 1.6:** operator configures the runtime-config record (desired state).
- **Bar 1.7:** operator installs; the materializer projects the derived MCP server override + internal-host allow-list rows.
- **Bar 1.8:** decision-history evidence confirms `mcp.override.set` and `mcp.allowlist.add`; the proof harness no longer inserts those derived rows directly.
- **Bar 1.9-1.10:** cold restart, then `list_tools` + `call_tool(describe_table owner=COGNIC table=EMPLOYEES)` succeed and the registry row reaches `discovery_status=auth_ready`. -> **`PROOF M4 (BAR 1) PASS`**

### Bar 2 (negative gates) — PASS
- **Not approved / not allow-listed:** install refuses with HTTP 409 + `lifecycle_transition_invalid_state_pair`.
- **Not configured:** install refuses with HTTP 409 + `install_runtime_config_missing`.
- **Vault OAuth ref absent:** install refuses with HTTP 409 + `install_runtime_config_vault_ref_unresolved`.
- **Signature red:** approve refuses with HTTP 412; the signature gate is non-overridable. -> **`PROOF M4 (BAR 2) PASS`**

### Bar 3 (disable, re-enable, revoke) — PASS
- **Disable:** operator disable retracts the derived carve-outs; after a cold restart the MCP resource leg is refused and `discovery_status=refused`.
- **Re-install:** disabled -> installed re-enable restores materialization; after a cold restart the pack returns to `auth_ready` and `call_tool` succeeds.
- **Revoke:** operator revoke retracts the carve-outs again; after a cold restart discovery is `refused`, and install-after-revoke returns 409 terminal refusal. -> **`PROOF M4 (BAR 3) PASS`**

### Live findings cleared
The green M4 run followed a deliberately preserved failure trail in this file. The proof surfaced real harness / substrate / pre-merge-integration issues, each fixed and pinned before the PASS run:
1. **Migration Job diagnostics + image permissions:** the proof migration path needed better diagnostics and the AgentOS proof image needed readable copied source / pyproject files when overlaying current branch code into the image.
2. **Proof runner robustness:** Docker/GitHub fetches needed retry guards; the runner gained image-reuse / AgentOS-rebuild modes to separate proof logic from transient network pulls.
3. **Runtime-config derived-key split:** install initially materialized the MCP override under the lifecycle record UUID, while the MCP host reads overrides by server/distribution id (`cognic-tool-oracle-schema`). The materializer and operator route now pass distinct lifecycle/config keys and derived server-id keys; Bar 1.8 and Bar 1.10 are the live proof.
4. **Fail-open saga hardening:** install is transition-first and materialize-after, so a crash or failure cannot leave callable-but-not-installed state; disable/revoke retract first and fail closed on post-transition status-write failures.
5. **MCP authz untouched:** the proof changes did not change `protocol/mcp_authz.py`; callability changed through the existing override + internal-host allow-list path.

### Honesty boundary
- "PASS" means the **operator-grade pack install flow** is proven on `kind`: no direct DB seed for pack lifecycle state or derived MCP carve-out rows, real operator API lifecycle, real runtime-config materialization, real disable/re-enable/revoke callability changes, and real negative gates.
- OAuth material is still **operator-provisioned by reference** in Vault for M4; M4 validates and consumes those references, but does not introduce a secret-writing operator API.
- This does **not** claim the production AKS platform (M15/M24), an end-to-end bank LLM-agent loop using tools/skills (M8), or every pack type (M5/M6/M7/M13). It proves the operator install governance spine for a released signed MCP tool pack.

## M5 — Real hook pack proof — PASS

**2026-07-02 — M5 proven: the released signed `cognic-hook-schema-guard@v0.1.0` hook pack was trust-registered + `HookRegistry`-admitted at boot in a deployed `kind` AgentOS, and its two arg-gated `dlp_pre` hooks enforced the MCP `call_tool` path — permitted arguments execute, a forbidden argument is refused before the tool runs, and a raising hook fails closed.**

> M5 wires the previously DORMANT Sprint-7A2 hook subsystem (`packs/hooks/*`, never called in the deployed runtime) onto `MCPHost.call_tool`: at boot the kernel discovers the hook pack as the `cognic.hooks` pack kind, cosign-verifies it against its per-pack trust root, admits its `[hooks]` declarations into a `HookRegistry`, and builds the `DLPGuard` the MCP host consults. On every governed `call_tool`, `MCPHost._dlp_pre_scan` runs the calling pack's declared `dlp_pre_hooks` over the canonical-serialized arguments BEFORE any token / session / transport work.

### Run metadata
- **Date:** 2026-07-02T15:38:44Z (operator-run, env-gated)
- **Command:** `COGNIC_RUN_PROOF_M5=1 ./infra/proof-m5/run-proof-m5.sh` -> **`runner_exit=0`**, **`PROOF M5 (ALL BARS) PASS`**
- **Run log:** preserved locally at `scratchpad/proof-m5-PASS-run2.log`; the durable pass markers are recorded below.
- **Released packs (released assets only, never built in the proof):**
  - `cognic-hook-schema-guard@v0.1.0` — wheel sha256 `1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432`, `cosign.pub` sha256 `e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49`.
  - `cognic-tool-oracle-schema@v0.2.0` — wheel sha256 `2961ce5d4aaf97425ab5851670f65e76c64164a5922b99d6f0e982a634be0439`, `cosign.pub` sha256 `43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78` (unchanged from v0.1.0). Both downloaded from their public GitHub Releases by `stage-packs.sh`; all four digests verified fail-closed before staging.
- **Topology:** kind cluster `cognic-proofm5`, Helm overlay `infra/proof-m5/`, the bundled backends, in-cluster Oracle XE (`gvenzl/oracle-xe:21-slim`, `XEPDB1`, seeded `COGNIC.*` schema), the released oracle MCP pack at ClusterIP `10.96.0.51`, and the proof RS256/JWKS AS at `192.88.99.9`. Tenant `proof-m5`.
- **Two-pack split (spec §6):** the `cognic-tool-oracle-schema@v0.2.0` TOOL is operator-installed through the full M4 lifecycle (submit -> distinct-reviewer claim/approve -> operator allow-list -> configure -> install -> materialize -> cold roll); the `cognic-hook-schema-guard@v0.1.0` HOOK pack is **trust-register + registry-admit ONLY** — baked into the kernel image, discovered + cosign-verified at boot, never through the portal pack-lifecycle API.

### Hook-pack admission (asserted at both boots) — PASS
- `GET /api/v1/system/plugins?tenant_id=proof-m5` reports `cognic-hook-schema-guard` as `kind=hooks status=registered` (attestation `grade=partial` — the proof-context supply-chain grade; the cosign signature is real-verified against the staged per-pack `hook-packs/cognic-hook-schema-guard/cosign.pub`). A negative sweep of the pod logs for hook-admission / DLP-guard failure markers is empty. This exercises the M5 kernel changes end-to-end: the `cognic.hooks` fourth pack kind (ADR-002 amendment) and the per-pack boot trust root (`harness/registry_boot._resolve_pack_trust_root`).

### Bar 1 (permitted arg -> hook allows -> tool executes) — PASS
- `call_tool(describe_table, owner=COGNIC, table=EMPLOYEES)` -> HTTP 200; the response carries `FULL_NAME` (the EMPLOYEES column metadata), an `audit.tool_invocation` success row is present, and `discovery_status=auth_ready`. The `dlp_pre` hook ran and ALLOWED, and the tool executed. -> **`PROOF M5 (BAR 1) PASS`**

### Bar 2 (forbidden arg -> refused before the tool) — PASS
- `call_tool(describe_table, owner=COGNIC, table=__FORBIDDEN__)` -> **HTTP 403**, `detail.reason=dlp_pre_refused`, `detail.policy_reason=forbidden_schema_arg`.
- **Refused before the tool:** the `audit.tool_invocation` success-row count is unchanged by the call (no tool execution); the newest evidence row is `audit.tool_invocation_refused` with `refusal_reason=dlp_pre_refused`, attributed to `dlp_failed_hook_id=refuse_forbidden_schema_arg`, carrying `dlp_policy_input_digest=cc09ae4e06af...` (sha256).
- **Digest-only:** a sweep of `audit_event` + `decision_history` for the literal `__FORBIDDEN__` returns zero rows — the argument plaintext never enters the evidence chain; only the digest correlates the call. -> **`PROOF M5 (BAR 2) PASS`**

### Bar 3 (raising hook -> fail closed) — PASS
- `call_tool(describe_table, owner=COGNIC, table=__EXPLODE__)` -> **HTTP 409**, `detail.reason=dlp_pre_failed`. The first hook passes; `explode_schema_guard` raises; the kernel fails CLOSED (a broken hook is a refusal, never a silent bypass — Wave-1). The `audit.tool_invocation` count is unchanged (no tool execution); the refusal row is `dlp_pre_failed` attributed to `dlp_failed_hook_id=explode_schema_guard`, digest `e32a369a736c...`; the `__EXPLODE__` literal is absent from all evidence rows. -> **`PROOF M5 (BAR 3) PASS`**

### Live findings cleared
- **Run 1 — transient astral.sh IPv6 blip (infra, not M5):** the first attempt failed at the deps-base image build on `ADD https://astral.sh/uv/0.5.29/install.sh` with `connect: no route to host` (an IPv6 route to Cloudflare), after the runner's own 3 retries. Two docker-build canaries diagnosed it as transient: PyPI was reachable (3.2s), and the identical astral.sh `ADD --no-cache` succeeded on retry minutes later. No code or environment change was made; run 2 built clean. Staging + all four release digests PASSED on both runs. This is a single transient network retry, not an M5 defect.
- Zero deploy / harness findings past the build stage — the proof-m5 runner + `proof_m5` app were modeled faithfully on the M4 proof.

### Honesty boundary
- "PASS" means the **DLP hook enforcement path** is proven live on `kind`: a released signed hook pack is trust-registered as a first-class pack kind, cosign-verified against its own per-pack trust root, admitted into the runtime `HookRegistry`, wired into the `DLPGuard` the MCP host consults, and its `dlp_pre` hooks decide real `call_tool` invocations (allow / policy-refuse / fail-closed) with digest-only evidence and no tool execution on refusal.
- The hook pack is **trust-register + registry-admit only**; an operator enable/disable lifecycle for hook packs (M4-style) is a documented follow-up (spec §8), not an M5 requirement.
- Unlike M3/M4 (zero `src/cognic_agentos` change), M5 REQUIRED kernel changes — the dormant-hook wiring onto `call_tool`, the `cognic.hooks` pack kind, and the per-pack boot trust root — each landed under the critical-controls coverage gate with `protocol/mcp_authz.py` byte-identical throughout.
- This does **not** claim the production AKS platform (M15/M24), an end-to-end bank LLM-agent loop (M8), or the executable-skill / workflow / agent pack types (M6/M7/M13).

## M6 — Governed agent skill proof (M6+M7) — PASS

**2026-07-04 — M6+M7 proven: the released signed `cognic-skill-schema-summary@v0.1.0` skill pack (an agentskills.io `SKILL.md` package with one deterministic `Skill.execute()` action) was trust-registered + hosted at boot in a deployed `kind` AgentOS, and its executable action ran FULLY SANDBOXED (`--network none`, no ambient credentials), composing the operator-installed `cognic-tool-oracle-schema@v0.2.0` MCP tools exclusively through the kernel-side broker — declared tools execute end-to-end, an undeclared tool is refused before `MCPHost.call_tool`, and direct outbound egress from the action is blocked fail-closed.**

> M6 (merged with M7 per ADR-025) makes governed agent skills real: the kernel hosts the open `SKILL.md` standard (frontmatter validated, `[skill].declared_tools` cross-checked against registered MCP servers, surfaced on `/api/v1/system/plugins` `hosted_skills`) while the pack's `cognic.skills` executable action NEVER loads into the kernel process — the executor runs it inside a cosign-admitted immutable sandbox runtime image, and its ONLY channel out is a per-invocation `0700` Unix-socket broker that enforces `declared_tools` per call and routes to `MCPHost.call_tool` with the invocation's bound tenant/actor, so OAuth / DLP hooks / audit apply automatically downstream (the full M5 governance, inherited not bypassed).

### Run metadata
- **Date:** 2026-07-04 (operator/controller-run, env-gated). Two consecutive passing runs: run 21 (first PASS) + **run 22 (ratification against the final kernel state)** — `COGNIC_RUN_PROOF_M6=1 ./infra/proof-m6/run-proof-m6.sh` → **`runner_exit=0`**, **`PROOF M6 (ALL BARS) PASS`** both times.
- **Released packs (released assets only, never built in the proof; all digests verified fail-closed by `stage-packs.sh`):**
  - `cognic-skill-schema-summary@v0.1.0` — wheel sha256 `d747b5e7ea5ccce23649281d93623bd1fd6316867e63f22e329d423dd07118aa`, `cosign.pub` sha256 `6e29b37dd3f31b68ad0eac569a53786e1ada43eeb75db63647dda8e52dff1a12`.
  - `cognic-tool-oracle-schema@v0.2.0` — wheel sha256 `2961ce5d4aaf97425ab5851670f65e76c64164a5922b99d6f0e982a634be0439`, `cosign.pub` sha256 `43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78`.
  - `cognic-hook-schema-guard@v0.1.0` — wheel sha256 `1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432`, `cosign.pub` sha256 `e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49` (the M5 DLP hooks stay live on the governed path the broker routes through).
- **Topology:** kind cluster `cognic-proofm6`, Helm overlay `infra/proof-m6/`, bundled backends + Redis, in-cluster seeded Oracle XE, the released oracle MCP pack at ClusterIP `10.96.0.51`, the proof RS256/JWKS AS at `192.88.99.9`, tenant `proof-m6`. Sandbox substrate: DockerSibling on the host daemon with the dual-container topology — workload (`--network none` + sandbox-private bridge) + egress-proxy sidecar; broker socket dir bind-mounted via `SandboxPolicy.writable_mounts`.
- **Sandbox images REAL-admitted:** both canonical images re-homed to the proof TLS registry + cosign-signed under the proof canonical key and verified by the un-bypassed admission gate — runtime `sandbox-runtime-python@sha256:44b45a3f…` (bakes the branch SDK overlay + the released skill wheel), proxy `sandbox-egress-proxy@sha256:eb4ea75b…`.
- **Skill hosted at boot (both boots):** `cognic-skill-schema-summary kind=skills status=registered skill_id=schema-summary declared_tools=['cognic-tool-oracle-schema/list_tables', 'cognic-tool-oracle-schema/describe_table']`; the oracle TOOL is operator-installed through the full M4 lifecycle (submit → distinct-reviewer approve → allow-list → configure → install → materialize → cold roll; SETUP 8 asserts the carve-out rows are install-materialized, not seeded).

### Bar 1 (composition works — declared tools, sandboxed, dual-layer evidence) — PASS
- `POST /api/v1/skills/schema-summary/invoke` (`owner=COGNIC`, mode=normal) → **HTTP 200** + the fixed deterministic summary (schema/table_count/tables with column metadata composed from `list_tables` + `describe_table` per table).
- Dual-layer evidence: execution-layer `audit.tool_invocation` rows `outcome: ok` for every broker-mediated governed call; instruction-layer `skill.invoked` row `terminal_state=completed` with **digest-only** payload (`arguments_sha256=347d977b69e4…`, stdout digested — raw args/results never enter the chain). → **`PROOF M6 (BAR 1) PASS`**

### Bar 2 (undeclared tool refused BEFORE the governed call) — PASS
- mode=forbidden probes `cognic-tool-oracle-schema/get_constraints` — a REAL tool on the installed pack, deliberately NOT in `declared_tools` → **HTTP 403 `skill_tool_not_declared`**; the broker refuses at its per-call declared-tools gate (§5.4 invariant #11), `get_constraints` is **never invoked**, and the `audit.tool_invocation` count is unchanged (no token minted, no tool touched). → **`PROOF M6 (BAR 2) PASS`**

### Bar 3 (isolation holds — mandatory) — PASS
- mode=exfil attempts one direct outbound HTTP request from inside the action → blocked under `--network none` (the egress proxy is the only route and the skill sandbox's allow-list is empty), surfacing as **HTTP 502 `skill_runtime_error` fail-closed** with no success marker anywhere in responses or evidence. → **`PROOF M6 (BAR 3) PASS`**

### Live-findings ledger (the C4 iteration arc, runs 4-22)
The proof drove five CC kernel slices, each committed standalone under the full gate (fresh `--cov-branch` critical-controls coverage 143/143, mypy + ruff clean, `protocol/mcp_authz.py` byte-identical, TM-revert-proven pins):
- **#13 → `3e942b2`** — ADR-016 canonical-license carve-out completed at BOTH egress-proxy sidecar admission sites (the 2026-05-29 amendment had landed only at `admission.py`; cosign still verifies, tenant/pack images keep the license gate).
- **#14/#15 → `ab67a29`** — `SandboxPolicy.writable_mounts` was declared-but-never-enforced (audit-projection only; the broker socket mount was silently dropped while chain evidence recorded it). Docker now renders real `:rw`/`:ro` binds on create() AND wake(); K8s FAILS CLOSED (`sandbox_writable_mounts_unsupported_on_backend`, enum 42→43); runner-stderr diagnosability WARNING.
- **#16 → `36e8798`** — the broker's downstream-failure arm shipped the real exception to the sandbox (which discards it) and logged NOTHING kernel-side; now `skill.broker.tool_invocation_failed` WARNING (safe fields; bounded detail for known MCP exceptions, sha256 otherwise).
- **#17a/b/c → `2f36bfb`** — the governed result path could never frame a REAL MCP result: the host conformer returned the mcp SDK `CallToolResult` pydantic model raw and the broker's stdlib `json.dumps` frame arm refused in-band, silently (proven by sha256-matching the 71-byte runner frame against the chain row's `stdout_sha256`). Now `_project_tool_result` (isError fail-closed → `structuredContent` → single-TextContent JSON-object parse [FastMCP 1.27 bare-`dict` handlers produce NO structured output — the live oracle realization, pinned by a real in-memory FastMCP e2e test] → JSON-mode envelope → passthrough), the `skill.broker.tool_result_not_frameable` WARNING on the frame arm, and `tool_request_id` keys (the observability `_ContextFilter` owns `record.request_id` and clobbers same-named extras).
- **#18 → `dc5dba5`** — image-declared Docker HEALTHCHECKs execute inside the sandbox with the sandbox env (incl. `HTTP_PROXY`): an inherited check's loopback GET was proxied to the egress sidecar, refused, and the fail-closed egress audit discarded exit-0 skill runs as false `egress_host_not_allow_listed` violations. The backend now sets `Healthcheck: {"Test": ["NONE"]}` on BOTH sandbox-created containers; **verified live in run 22 on all six sandbox containers** — the proxy sidecar's image still declares its healthcheck and the backend override disabled it regardless (`NO_PROXY` stays forbidden per the anti-bypass doctrine; K8s structurally unaffected).
- Proof-harness fixes (committed `54183db`): syft via busybox wget + sha256 (finding #12 — the runtime stage has no curl); `HEALTHCHECK NONE` on the skill-runtime image (finding #18's proof half); diagnostics hardening (per-not-ready-pod describes; `sandbox.%` decision-row capture — the refused egress host lives only on `sandbox.policy.violated.payload.proxy_log`). Runs 17/18 were environment flakes (in-cluster DNS during the ollama model pull), not defects.
- Product follow-ups on the books: the default-adapters base lacks `syft` (flagged, finding #1); `#17c-executor` — four `extra={"request_id": …}` sites in `core/skill/executor.py` subject to the same ContextFilter clobber (diagnostics-only, standalone slice).

### Honesty boundary
- "PASS" means the **governed agent-skill execution path** is proven live on `kind`: a released signed `SKILL.md` pack is hosted + validated; its single signed `cognic.skills` action executes fully sandboxed; every tool call is broker-mediated, per-call declared-tools-enforced, and lands the full M5 governance (OAuth / DLP / audit) downstream; refusal and isolation negatives hold with digest-only evidence.
- **M7's instruction-layer consumption by an LLM agent (the governed assignment path feeding `SKILL.md` content to an agent) is explicitly M8** per the ADR-025 M6+M7 merge — this proof validates + hosts + audits the instruction layer but does not feed it to an LLM. Arbitrary bundled `scripts/` execution is likewise out of scope (ADR-025: the single governed executable surface is the signed Python action).
- Unsigned/untrusted pack refusal rides the SAME per-pack boot trust gate proven live at M5; malformed-`SKILL.md` warn-skip (not hosted → invoke 404s) is unit-pinned at `tests/unit/harness/test_skill_host.py`.
- M6 REQUIRED kernel changes (Part A: broker + executor CC modules; plus the five C4 slices above) — all under the critical-controls gate (143 files) with `protocol/mcp_authz.py` byte-identical throughout.
- This does **not** claim the production AKS platform (M15/M24), the bank LLM-agent loop (M8), or workflow/agent pack types (M13). The K8s skill realization (same-Pod sidecar + emptyDir) is a documented forward item — the K8s backend fails closed on `writable_mounts` until it lands.

## M8 — Governed agent loop (ADR-027) — PASS

**2026-07-08 — M8 proven live on `kind`: a declarative NLP agent pack (`cognic-agent-bank-analyst@v0.1.0` — persona + *requested* capability sets, no agent code beyond an inert marker) ran a KERNEL-OWNED single-shot reasoning loop against a REAL cloud model (LiteLLM -> OpenAI `gpt-4o`), selected + read a hosted `SKILL.md` instruction skill, authored read-only SQL over that skill's governed views, invoked the operator-installed `cognic-tool-oracle-schema@v0.3.0` MCP tool under a kernel-signed query-context, and answered from the returned figures — while the kernel's assignment + entitlement + policy chokepoint gated every dispatch and every denial of an unassigned skill / unentitled scope was visible and audited.**

> M8 (ADR-027) hosts the open agent-pack standard while the KERNEL owns the loop and every dispatch decision. The pack declares a persona + *requested* skills/tools; grants live kernel-side in `agent_entitlements` (an ingestion invariant refuses any grant beyond the requested set). The reasoning loop is bounded (max-steps / token-budget / wall-clock), progressive-disclosure (only granted-skill DESCRIPTIONS reach the model; bodies arrive ONLY via the dispatch-gated `read_skill` built-in), dual-identity (agent rides the payload, human originator rides `actor_id`), and digest-only evidenced. The two data-plane guards — the tool's query-context OBO binding and its SQL allow-set — are separately proven.

### Run metadata
- **Date:** 2026-07-08 (operator/controller-run, env-gated). `COGNIC_RUN_PROOF_M8=1 ... ./infra/proof-m8/run-proof-m8.sh` -> **`runner_exit=0`**, **`PROOF M8 (ALL BARS) PASS`** (run 16). BAR-5 anchor run `agent-run-7eaf3f8059ea46adb0263772270ddb60`.
- **Released packs** (released assets only, never built in the proof; every digest verified fail-closed by `stage-packs.sh`, pinned in `tests/unit/infra/test_proof_m8_structure.py`):
  - `cognic-tool-oracle-schema@v0.3.0` — wheel `a520e4374408513033d589e68cfff2011cbc129575de82147a40427ee3e4a4ed`, `cosign.pub` `43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78`.
  - `cognic-skill-customer-data@v0.1.0` — wheel `253e1d83f9e2507cf65abf7993795fa42dc86bd1f60f7545ad805dd85c99d41c`, `cosign.pub` `2ac85879bf0bc8bb01fac6547210c0ae1b391af789614785cd02240486dbe499`.
  - `cognic-skill-financial-data@v0.1.0` — wheel `15b26a81911b0704965aaf5b4287c0a26feb01a0107e89d9cbc0b420eb416567`, `cosign.pub` `dc3a1f0f0477b3ceb2699d8654a01432214abe034834a394424b7b124913e34d`.
  - `cognic-skill-cards-data@v0.1.0` — wheel `a4b6f4c3ad330a116be47a59eec16fcb1f1b93904d41361c8e607bcfca5f154b`, `cosign.pub` `99307c338f8922937e9bed3dcbcd014621eadc4980b8d78acc1a89fe7ff001e6`.
  - `cognic-skill-atm-recon@v0.1.0` — wheel `f53e290ad61b614ec4ba55f9c7d7e86f0e7e7b6870595492d5251092dd35c7ad`, `cosign.pub` `e1b0c58aa95a355bb418a5ef7b847dc7702145babd280e6db521137f46fe0c59` (hosted but **NEVER granted** — the standing BAR-2 negative).
  - `cognic-agent-bank-analyst@v0.1.0` — wheel `77be5140a11e25970b28e13be9df9d33d4cf7f16ee267d27061e09fa96bcdec9`, `cosign.pub` `532fe8e2181008be86a06c19c3552aedd901a74fd9da3f405ab8e119e783929e`, dual-custody `agent-card.pub` `c691d31693459a52226d7190b07dd07e1fdb21a1abdf0324a9225c7c2558d214` + `agent-card.jws` `71207eaf5956d08a0b9bc1381bce75113478295c5b968c18b600dc16efb0e13a` (the JWS trust root is NEVER `cosign.pub` — M8 finding #4 custody split).
  - `cognic-hook-schema-guard@v0.1.0` (reused M5 release) — wheel `1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432`, `cosign.pub` `e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49` (the M5 DLP hooks stay live on the governed tool path).
- **Topology:** kind cluster `cognic-proofm8`, Helm overlay `infra/proof-m8/`, bundled backends + Redis + otel-collector, in-cluster seeded Oracle XE (RETAIL/CARDS/FIN schemas: base tables + governed views + proxy users `AN_AMIR`/`AN_SARA` via `GRANT CONNECT THROUGH`), released oracle MCP pack at ClusterIP `10.96.0.51`, RS256/JWKS AS at `192.88.99.9`, tenant `proof-m8`. LiteLLM tier-1 -> OpenAI `gpt-4o` (external cloud; operator-supplied key, never image-baked).
- **Surfaces at boot:** 7 packs registered (1 tool / 1 hook / 4 skills / 1 agent); the 4 instruction skills hosted via the ADR-002 manifest-walk discovery arm; `bank-analyst` hosted with requested skills `[customer-data, financial-data, cards-data]` (NEVER atm-recon) + tool `run_readonly_query`, tier `customer_data_read`. Entitlement seed: amir -> {retail_analytics, financials}; sara -> {cards_analytics, retail_analytics}; `atm_recon` entitled to NOBODY.
- **Oracle tool operator-installed** through the full M4 lifecycle (submit -> distinct-reviewer approve -> allow-list -> configure -> install -> materialize -> cold roll); SETUP 8 asserts the carve-out rows are install-materialized, not seeded.

### BAR 1 (governed loop e2e) — PASS
As `analyst.amir`, "top 10 customers by deposit balance this quarter" -> HTTP 200 `terminal_state=completed`; the answer carries the seeded top-10 (Ayesha Khan ... Javeria Tariq; rank-11 Kamran Zafar absent), `steps_used=3`. Evidence asserted: `agent.run.started` -> a `read_skill` dispatch (builtin, ok) -> a `run_readonly_query` dispatch (tool, ok, `scope_id=retail_analytics`, `args_sha256`) -> downstream `audit.tool_invocation` -> honesty-ledger `external=true`/`resolved` -> task-tier `memory.write` chain row -> `agent.run.completed`, all dual-identity (agent + originator). -> **`PROOF M8 (BAR 1) PASS`**

### BAR 2 (unassigned skill — audited denial) — PASS
An authorization probe drives `read_skill("atm-recon")` (hosted but never granted) -> the A10 `read_skill` sub-gate refuses `agent_capability_not_assigned`, **audited** on a digest-only dispatch row (attempted skill_id pinned via `args_sha256`); zero successful atm-recon read anywhere, zero `atm_recon`-scoped tool execution, graceful answer. -> **`PROOF M8 (BAR 2) PASS`**

### BAR 3 (unentitled scope — m:n both directions) — PASS
Amir's cards question -> dispatch row refused `agent_scope_not_entitled` (`scope_id=cards_analytics`) + a "not available" answer; the SAME question as `analyst.sara` -> completed through `cards_analytics`; sara's retail question -> completed through the SHARED `retail_analytics` (m:n both ways, on identity not scope-shape). -> **`PROOF M8 (BAR 3) PASS`**

### BAR 4 (SQL guards — tool-layer defense-in-depth, deterministic) — PASS
The oracle tool's two SQL guards, each proven **deterministically** via a direct MCP tool-invocation carrying a valid, args-bound kernel query-context token (see Boundary #1). Leg 1 — a raw-table SELECT under a token authorizing ONLY the governed view -> `agent_sql_object_out_of_scope` at the object allow-set (asserted NOT an earlier token/replay/args/DLP gate). Leg 2 — part A: the agent DECLINES the DML steer (correct "no DML ever" persona; zero DML dispatch executed); part B: the exact DELETE under a valid token -> `sql_not_select_only` at SQL-parse, before any DB connection. Target rows untouched. -> **`PROOF M8 (BAR 4) PASS`**

### BAR 4b (DB backstop — direct proxy sessions) — PASS
Direct Oracle proxy sessions (`sqlplus` in the XE pod): governed-view SELECT succeeds as `cognic[AN_AMIR]`; raw-table / cross-scope / ATM-view SELECTs ORA-denied for BOTH `AN_AMIR` and `AN_SARA`; the main-path parser is never touched (tool-execution count unchanged). -> **`PROOF M8 (BAR 4b) PASS`**

### BAR 5 (provider governance) — PASS
On the BAR-1 run: 3 `llm.gateway.completion` otel spans carry `agent_workforce_id=bank-analyst` + `external=true` (collector-recorded); cloud-policy ALLOWED (0 `gateway.cloud_policy_denied`); strict external honesty-ledger rows (`resolved` provenance, real upstream `openai/gpt-4o`). -> **`PROOF M8 (BAR 5) PASS`**

### Evidence-row samples (C3 diagnostic / evidence-query samples)
Representative rows from the runner's failure-path diagnostic dumps + evidence-queries captured across the run-11...16 iteration; run 16 asserts the identical shapes on its success path (on a PASS the runner prints only `Bar N OK` — the rows below are diagnostic captures, NOT run-16 success-log lines):
- BAR-1 tool dispatch — `{... "capability_ref": "cognic-tool-oracle-schema/run_readonly_query", "outcome": "ok", "scope_id": "retail_analytics", "args_sha256": "485cd027...", "result_sha256": "a187af21..." ...}`
- BAR-1 skill read — `{... "capability_ref": "read_skill", "capability_kind": "builtin", "outcome": "ok", "result_bytes": 5155 ...}`
- BAR-3 refusal — `{... "capability_ref": "cognic-tool-oracle-schema/run_readonly_query", "outcome": "refused", "refusal_reason": "agent_scope_not_entitled", "scope_id": "cards_analytics" ...}`
- downstream audit — `audit.tool_invocation | {"outcome": "ok", "pack_id": "cognic-tool-oracle-schema", "scopes": ["oracle_schema.read"], "tool_name": "run_readonly_query" ...}`
- honesty-ledger / span — `agent-run-...-s2 | cognic-tier1-proof-m8 | openai/gpt-4o | external=true | resolved | ok`

### Live-findings ledger (the C3 iteration arc, runs 1-16)
Eight findings resolved — five kernel critical-controls slices (each committed standalone under the full gate: fresh `--cov-branch` critical-controls coverage 149/149, mypy + ruff clean, `protocol/mcp_authz.py` byte-identical, TM-revert-proven pins) — plus four proof-harness fixes:
- **#1 (kernel CC)** — instruction-skill manifest-walk discovery arm (`protocol/plugin_registry.py`): content-pack skills with ZERO `cognic.*` entry points are discovered from a signed manifest declaring `[pack].kind="skill"` + `[skill].mode="instruction"`.
- **#2 (proof/pack design)** — BAR 3 needed a granted `cards_analytics` teacher; `cognic-skill-cards-data@v0.1.0` was authored/released and granted to `bank-analyst` while `cognic-skill-atm-recon@v0.1.0` stayed released + hosted but **NEVER granted** as the BAR-2 negative.
- **#3 (kernel CC)** — sign/verify wheel-integrity instruction arm (`cli/_wheel_integrity.py` / `verify.py` / `_load_probe.py` / `sign.py`): instruction wheels (no `entry_points.txt`) sign + verify + real module-import probe.
- **#4 (kernel CC)** — AgentCard-JWS custody split (`cli/sign.py` / `verify.py` + `core/config.py`, ADR-016 amendment): separate JWS signing key / trust root from cosign; tracked `agent-card.pub`; joserfc -> base deps.
- **#5 (kernel CC)** — private-infrastructure image admission (`sandbox/catalog.py`): `cosign verify --private-infrastructure=true` for the proof-local registry (no public Rekor tlog).
- **#6 / #7 (proof config)** — LiteLLM master-key via `vault://`, then no-master-key + OpenAI-coherent defaults across values + runner in lockstep.
- **#8 (kernel CC)** — gateway alias-echo provenance (`llm/gateway.py`, ADR-007 amendment): the real LiteLLM proxy echoes the requested deployment ALIAS as the response `model`; when it equals the exact dispatched alias the forward preflight resolution IS authoritative provenance (records the real `openai/gpt-4o`) — the ONLY relaxation; every other provenance gap stays fail-closed.
- **Harness fixes** (proof runner, no kernel change): `json_field` arg-order (BAR-1 false-fail on a *completed* run); BAR-2 reframed as an authorization probe (the persona correctly declines a naive ask — the `read_skill` call is made the deliverable so the kernel gate fires + audits); BAR-4 legs 1 & 2 converted to deterministic minted-token tool-guard probes (escape probes that depend on GPT-4o authoring out-of-bounds SQL are unstable — see Boundary #1/#5).

### Boundary / Not Proven
"PASS" means the **core M8 claim** is proven live on `kind`: a governed single-shot agent loop over hosted `SKILL.md` skills + a governed MCP tool, driven by a REAL cloud model, with the kernel's assignment / entitlement / policy chokepoint enforcing every dispatch and every denial of an unassigned skill (BAR 2) or unentitled scope (BAR 3) **visible and audited**. It does NOT claim more:
1. **BAR 4's SQL guards are proven at the TOOL layer via proof-minted query-context tokens, NOT via the agent authoring escape SQL.** The proof demonstrates the oracle tool refuses out-of-scope objects (`agent_sql_object_out_of_scope`) and non-SELECT SQL (`sql_not_select_only`) **even under a valid kernel-signed authorization context** — tool-layer defense-in-depth, deterministic. It does NOT exercise "the agent tries to escape and is refused end-to-end" (that path is model-dependent; the tool WOULD refuse it, but the run does not drive it).
2. **The minted token's `objects` are proof-constructed** (one governed view), not a byte-replica of the scope-objects the kernel stamps for amir's real `retail_analytics`. It proves the tool's allow-set LOGIC; BAR 1 separately proves the kernel stamps a WORKING token for the entitled scope. Two facts, not one.
3. **BAR 4 Part-A agent-path checks are tolerant** — they require only a graceful, non-crashing answer; "no leak" is checked as *no stack-trace / ORA error*, NOT as "no raw PII in the answer" (nothing leaks in practice — the agent declines or the tool refuses, and BAR 4b shows the DB denies — but the assertion itself is narrow).
4. **Pack approval used the governed gate-override path for 4 of the 5 lifecycle gates** (cosign signature REAL-verified; evaluation / adversarial / owasp / reviewer-ack overridden — the proof generates no eval/adversarial evidence). Audited + the M4 posture, not an organic 5-gate pass.
5. **BARs 1-3 are model-driven and inherently non-deterministic.** They have been stable across runs, but they depend on GPT-4o's behavior — exactly why BAR 4 was made deterministic. A future run could see model variance. Live-LLM proofs carry this property.
- This does NOT claim the production AKS platform (M15/M24), long-term / cross-session agent memory (M9 — this proof writes only a **task-tier digest** to the governed memory API + its `memory.write` audit row; richer long-term memory is M9), multi-step or multi-agent orchestration beyond the single-shot loop, or A2A. The M8 kernel changes rode the critical-controls gate (149 files) with `protocol/mcp_authz.py` byte-identical throughout.

## M8.5-A — Conversation substrate (ADR-028 vertical slice) — PASS

**2026-07-10 — `PROOF M8.5 SLICE (BARS 1-3) PASS` live on `kind` (run 6, exit 0).**

- **Kernel anchor:** `main @ 235daede6d1b7a99846c6339f2e234c85e6bd0cc` (M8.5 A/B/C1, PR #126) — the deployed kernel, pinned as the proof image label.
- **Proof revision:** `feat/m85-c2-kind-proof @ caab00bd` — the runner + structural-suite tree that executed (four C2 commits after the anchor — `7981da7c` authored the proof, three review-fix commits followed; zero kernel changes: `git diff main -- src/` empty, `protocol/mcp_authz.py` byte-identical).
- **Runner:** `infra/proof-m85/run-proof-m85.sh` — env-gated (`COGNIC_RUN_PROOF_M85=1`), provider key `COGNIC_PROOF_M85_TIER1_API_KEY` proven by the zero-spend `GET /v1/models` preflight (`HTTP 200`, log line 1) before any cluster work.
- **Log:** 533 lines, SHA-256 `9c6f17b35efce426ec5194920da327a2257b82116807037cad656717d9f533f9` (operator-held; deliberately not committed).
- **Deployment:** the proven proof-m8 bring-up verbatim, m85-named — the same SEVEN sha256-pinned signed releases, full M4 operator lifecycle for `cognic-tool-oracle-schema@v0.3.0`, Oracle XE + RS256/JWKS AS + Redis + LiteLLM → OpenAI `gpt-4o`, migrate to rev **0015**, the 0014 seed matrix (readback `4|4|4|0`), Step-0 hosted/registered surface asserts. The conversation substrate added no pack and no seed rows.
- **Spend:** four governed model-driven turns (BAR 1 × 2, BAR 3 × 2; BAR 2 is deterministic — no model call). Exact completion-call and token totals were not retained: the cleanup trap removes the cluster and its DB, and the success path echoes no usage.

### Bar evidence (log lines, verbatim)

```
  Bar 1 pin OK: prior_context_turns=2 + prior_context_sha256 recomputed from the kernel store
  Bar 1 pin OK: context lineage (seq=2 -> run -> started/completed; dispatches unconstrained) + dispatch lineage (seq=1 -> run -> ok retail dispatch)
  Bar 1 pin OK: question/answer sha256 digests on both turn rows equal the stored plaintext
  Bar 1 OK: two governed turns, context replay pinned mechanically, three-hop join + digests + dual identity verified
PROOF M8.5 SLICE (BAR 1) PASS
  Bar 2 OK: five forged fields 422 extra_forbidden (messages/history/prior_context/context/transcript); zero-loop pin held
PROOF M8.5 SLICE (BAR 2) PASS
  Bar 3 leg 1 OK: financials dispatched ok while the entitlement was live
  Bar 3 revocation OK: 1 -> 0 amir financials entitlement rows (mid-conversation)
  Bar 3 leg 2 OK: post-revocation financials dispatch refused (agent_scope_not_entitled), zero ok financials dispatches
  Bar 3 restore OK: amir financials entitlement back to exactly 1 row
PROOF M8.5 SLICE (BAR 3) PASS
PROOF M8.5 SLICE (BARS 1-3) PASS
```

### What each bar proved

- **BAR 1 (governed multi-turn e2e).** `analyst.amir` created a conversation with `bank-analyst` and drove two governed turns. Turn 2 contained **no entity name** and was answered via the replayed turn-1 context. Invariant mechanical pins, all tenant-scoped: the turn-2 `agent.run.started` row carried `prior_context_turns=2` and a `prior_context_sha256` the runner **recomputed independently** from the `conversation_turns` plaintext with the loop's exact `user:<question>\nassistant:<answer>` framing — and it MATCHED; the **context lineage** (`turn_completed(seq=2)` → run → started/completed) and the **dispatch lineage** (`turn_completed(seq=1)` → run → started/completed → ≥1 ok retail-scoped `run_readonly_query` dispatch with a 64-hex args digest) both resolved; `question_sha256`/`answer_sha256` on BOTH digest-only `conversation.turn_completed` chain rows equalled sha256 of the stored plaintext; dual identity held on every `conversation.%` and `agent.run.%` row. The model-driven acceptance criteria (turn-1 top-3 seeded names; the turn-2 rank-2 name) passed.
- **BAR 2 (record integrity — deterministic).** Five forged history fields (`messages` / `history` / `prior_context` / `context` / `transcript`) each returned **422 with a Pydantic `extra_forbidden` error naming the field** (invariant I-1: a client transcript is unrepresentable on the wire), and the zero-loop pin held — the `agent.run.%` count, the conversation's `turn_completed` count, and the wire `turn_count` were byte-identical across the probe block.
- **BAR 3 (mid-conversation revocation — the I-2 pin).** In a fresh conversation on the `financials` scope: turn 1 (a GL question) completed with an ok financials dispatch; the runner proved **exactly one** amir financials entitlement row, DELETEd it (readback 0); turn 2 asked a **fresh** financials question (branch P&L — not answerable from the replayed context) and returned HTTP 200 with ≥1 dispatch row `refused` / `agent_scope_not_entitled` / `scope_id=financials` and **exactly 0** ok financials dispatches — the envelope was re-resolved against CURRENT entitlements on that turn, never cached; the entitlement was restored (readback 1).

### Run ledger (five entries: four pre-pass events plus PASS; every CODE finding fixed, review-gated, and committed before the pass)

1. **Run 1 — one-time operator trust gate** (an operator prerequisite by design — NOT a code finding, no commit): the m85-named local TLS registry needed its `/etc/hosts` loopback + docker `certs.d` CA trust; the sudo-free runner refused with instructions; the operator ran the three commands once. No spend, no cluster.
2. **Run 2 — rotated provider key**: a stale `OPENAI_API_KEY` 401'd at BAR 1, ~25 minutes into a fully-green bring-up (zero token spend — the first completion refused at auth; the stack behaved correctly end-to-end: honest `upstream_error` ledger row, digest-only failed-turn evidence, closed-form 502). Fix (`3a8e569f`): the zero-spend key-validity preflight — bounded timeouts, bearer via stdin (never argv), four-way transport/auth/ok/unexpected diagnosis — refusing before any cluster work.
3. **Run 3 — evidence-read SQL crash**: both BAR-1 turns SUCCEEDED live (turn 2 named the rank-2 depositor from replayed context), then the combined evidence read crashed — PostgreSQL gives `->>` and `||` equal precedence, and the raw psql error escaped `bar_fail` under `set -e` with no capture. Fixes (`a97849f3`): the parenthesized read (validated against a throwaway `postgres:16-alpine` with the defective form reproducing the exact error as negative control) + the fail-capturing `PSQL()` helper (stderr under the private `$QC_TMP`; SETUP-8 reads converted; structural bypass scans).
4. **Run 5 — a false invariant in the bar itself**: turn 2 answered entirely from the replayed context with ZERO dispatches (`steps_used=1` — correct, desirable behaviour) and the old hop-3 pin wrongly required a turn-2 dispatch row. Fix (`caab00bd`, ruled): the two-lineage join above — the turn-2 dispatch count is deliberately unconstrained (0 = context reuse; ≥1 = legitimate re-verification); the dispatch join rides the turn that DID dispatch. The plan's Task 8 was amended to the ratified rulings in the same commit.
5. **Run 6 — PASS** (this section). Runs 1–5 spent four model-driven turns in total across runs 3 and 5; runs 1–2 spent none.

### Honesty boundary

1. **This is the VERTICAL-SLICE GATE (M8.5-A), not the M8.5 production proof.** ADR-028 BARs 4–7 (bounds/terminal refusal, erasure, safety hooks, SSE reconnect) are NOT run here — they are later M8.5 slices. Do not present this as "conversational agent production-proven."
2. **BARs 1 and 3 are model-driven at the answer level.** Their invariant evidence is the mechanical chain pins; the answer-content checks are mandatory functional acceptance criteria and the flake-prone half — a miss reads as model-behaviour failure, not governance failure.
3. **The turn-2 dispatch count is unconstrained** (run-5 ruling): zero means context reuse, one-or-more means legitimate re-verification; neither fails the bar.
4. **PT-3 posture on BAR 3:** revoking a scope mid-conversation does not un-disclose content already in the transcript (turn 1's answer stays in the replayed context by design; erasure is the M8.5-F pathway). The bar proves no FRESH data crosses the revoked scope.
5. **OTEL is inherited diagnostics only** (ruling R6): no M8.5 bar depends on spans.
6. **Proof-only wiring caveats carry from proof-m8 unchanged:** header-driven multi-actor binder, proof-staged trust roots, per-run query-context keypair, demo-grain scope→proxy identities, cloud toggles + provider key as operator env. The unit/CI layer separately covers the bounds + terminal-refusal + claim-fencing contracts (including the live-Postgres fencing canary in the CI postgres lane).

## M8.5-B — Harness enablement APIs (ADR-028 HP-1) — PASS

**2026-07-11 — `PROOF M8.5-B (READ APIS) PASS` live on `kind` (run 7, exit 0 — the first M8.5-B execution; zero findings).**

- **Kernel anchor = proof revision:** `feat/m85b-harness-enablement-apis @ 8e77ca16f267545ce2e2a808b684b11f1be33005` — a SINGLE revision for both (unlike M8.5-A's split anchor), and for the first time the image label was **verified live**: the runner computed the revision from a clean tree (both cleanliness guards — kernel-source AND proof-input — passed), passed it as the `KERNEL_GIT_SHA` build arg, and read the `io.cognic.proof.kernel-anchor` label back off the built artifact via `docker inspect` before deploy (log line 411).
- **Runner:** `infra/proof-m85/run-proof-m85.sh` — env-gated; the **rotated** provider key (the pre-fix key was revoked per the review rotation directive) proven by the zero-spend `GET /v1/models` preflight (`HTTP 200`, log line 1). The hardened custody window ran live: the exported key variable was dropped before the first child process, the key rode stdin + a `0600` file under the private per-run dir only, the Secret was created `--from-file`, and zero shared-`/tmp` artifacts exist (the response/status files live under `$QC_TMP`, removed by the trap).
- **Log:** 743 lines, SHA-256 `fb9e6536b2952dcac1303b82aead73c7a7984c67d7348958a76da71a711d18a1` (operator-held; deliberately not committed).
- **Deployment:** the M8.5-A bring-up verbatim, plus migrate to rev **0016** with the live schema readback — `alembic_version = 0016` AND the `turn_completed_request_id` correlation column AND both read-model indexes present (`1|2`, log line 641). The M8.5-A BARs 1–3 re-executed and re-passed on this tree in the same run; the READ section then served THAT record.
- **Spend:** four governed model-driven turns (the M8.5-A bars, unchanged). The M8.5-B READ section itself made **zero model calls** — it is deterministic and read-only over the record the bars produced.

### READ evidence (log lines, verbatim)

```
  M8.5-B READ 1 OK: both bar conversations listed with turn_count=2
  M8.5-B READ 1b OK: two limit=1 pages, disjoint, cover exactly the two bar conversations, walk terminates
  M8.5-B READ 1c OK: all three cursor probes refused 422 cursor_invalid
  M8.5-B READ 2 OK: both turns plaintext (non-null, erased_at null), ordered, token-attributed, runs match the wire
  M8.5-B READ 2b OK: seq 1 then seq 2 across pages under the frozen watermark 2
  M8.5-B READ 3 OK: four blocks, started<terminal ordering, >=1 ok retail dispatch inside the window, digests only
  M8.5-B READ 3b OK: turn-2 chain joined; dispatches observed (unconstrained): 2
  M8.5-B READ 4 OK: six-way byte-identical collapse; owner-visible turn_not_found stays distinct
  M8.5-B READ 5 OK: fully-scoped sara (same tenant) and zara (foreign tenant) both list empty
  M8.5-B READ 6 OK: list/transcript/chain access trails with identifiers + outcome; zero plaintext in the access lines
PROOF M8.5-B (READ APIS) PASS
```

### What each READ proved

- **READ 1/1b/1c (list + pagination + cursor hostility).** `analyst.amir`'s list carried exactly the BAR-1 and BAR-3 conversations (`turn_count=2` each); a `limit=1` cursor walk covered both in two disjoint pages and terminated; three hostile cursors — malformed base64url, wrong version (`{"v": 999}`), and a filter-mismatch replay (`state=closed` against a cursor minted unfiltered) — each refused `422 cursor_invalid`.
- **READ 2/2b (transcript).** Both turns returned with non-null plaintext, `erased_at` null, ascending seq, positive token attribution, `agent_run_id`s matching the wire, and the BAR-1 question prefix verbatim; `limit=1` pagination held the frozen watermark 2 across both pages. The full transcript was then persisted under the private run dir and became the READ-6 banned-marker source.
- **READ 3/3b (turn-chain join).** Turn 1 joined all four curated blocks with `started < terminal < turn_completed` ordering, every surfaced digest a true lowercase 64-hex, the started↔turn question-digest and terminal↔turn answer-digest couplings holding, ≥1 ok retail `run_readonly_query` dispatch inside the run window with valid args AND result digests. Turn 2 joined with `prior_context_turns=2` and its dispatch count deliberately unconstrained — **run 7 observed 2 (re-verification), where run 5 had observed 0 (context reuse): both legs of the run-5 ruling have now occurred live.**
- **READ 4 (the load-bearing proof).** Six-way byte-identical 404 collapse: unknown-id / cross-actor (`analyst.sara`) / cross-tenant (`analyst.zara`, tenant `proof-foreign` — the 7th proof role, fully scoped) × transcript + chain all returned the SAME `conversation_not_found` body byte-for-byte, while an absent turn on an OWNED conversation stayed the distinct owner-visible `turn_not_found`.
- **READ 5 (isolation on list).** Fully-scoped sara (same tenant, different creator) and zara (foreign tenant) both listed EMPTY — isolation is the storage WHERE clause, not the scope set.
- **READ 6 (access trails, no plaintext).** `portal.conversations.{list,transcript,chain}` access records carried identifiers + outcome (including the foreign reader's empty-read trail), and NO access-log line contained any ≥16-char fragment of any live transcript plaintext — both questions and both model answers — nor the static BAR-3 fragments.

### Run ledger (one entry)

1. **Run 7 — PASS on the first M8.5-B execution.** The review findings — 14 across the first two rounds, plus two round-3 completeness corrections — were fixed, review-verified, and committed BEFORE the run — `68f8bd64` (read-model adversarial hardening), `ef442518` (proof provenance + claim strength), `3f5c5283` (digest validation + coupling, CC), `8e77ca16` (custody/provenance/assertions incl. the key-isolation window). No findings surfaced during or after the run.

### Honesty boundary

1. **M8.5-B is HP-1 only** — the read API. HP-2 (bank-overlay `ActorBinder`/SSO) is an external overlay dependency; HP-3 (entitlement/data-scope admin API) is out of v1 (operator-seeded), per the checklist boundary.
2. **ADR-028 BARs 4–7 remain NOT run** (bounds/terminal refusal at the wire, erasure, safety hooks, SSE reconnect) — the M8.5-A vertical-slice posture carries; nothing here is pilot-ready.
3. **The M8.5-A honesty boundaries carry unchanged** (model-driven bars, PT-3 revocation posture, OTEL as inherited diagnostics, proof-only wiring caveats).
4. **The READ-6 plaintext scan is scoped to the `portal.conversations.*` access-log lines** — it proves the ACCESS LOG discipline, not a whole-pod-log guarantee (other log families are digest-only by their own reviewed contracts).
5. **`erased_at` was null on every turn read** because no erasure pathway exists yet (M8.5-F); the transcript surfaces the erasure SHAPE (nullable plaintext + timestamp), proven at the unit layer.

## Proof M8.5 slice — FAILURE (2026-07-13T15:50:26Z)

- Failed step: `STEP 0a — could not mint a real token for analyst.amir (PKCE flow failed against the live realm)`
- last API response (HTTP ):
```json
<no response captured>

```
- conversation.% chain rows (tail 10 — digest-only):
```
<none>
```
- conversations operational records (tail 6 — no plaintext):
```
<none>
```
- agent / dispatch / gateway reason markers:
```
<none captured>
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
<none>
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
<none>
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m15:50:09 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m15:50:09 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#         'The worst thing about this product is...'          #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:47546 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51546 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
<none>
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"3855587c7061d685a1b365844e2735d0182f0b78912dcee6cb9d7830b92322ac","refusal_reason":null,"registered_at":"2026-07-13T15:50:18.278141+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"8f81f71c60471aed4776df7dfec5ec0ac89d04ea6ad28eae820c305a4b5389f4","refusal_reason":null,"registered_at":"2026-07-13T15:50:18.532388+00:00","discovery_status":"unprobed"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-13T15:50:18.782750+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-13T15:50:19.030350+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-13T15:50:19.280807+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-13T15:50:19.535362+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-13T15:50:19.779210+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-13T15:50:20.035487+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-13T15:50:20.282774+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":9,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : a6e29790e69120d4
    ID             : 93d2121f11b9ef3a
    Name           : GET /api/v1/healthz http send
    Kind           : Internal
    Start time     : 2026-07-13 15:50:23.018084304 +0000 UTC
    End time       : 2026-07-13 15:50:23.01810547 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #9
    Trace ID       : 73957477a4c9e5969adfeb882395dca4
    Parent ID      : a6e29790e69120d4
    ID             : 025884df9c5862da
    Name           : GET /api/v1/healthz http send
    Kind           : Internal
    Start time     : 2026-07-13 15:50:23.018206595 +0000 UTC
    End time       : 2026-07-13 15:50:23.018213679 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #10
    Trace ID       : 73957477a4c9e5969adfeb882395dca4
    Parent ID      : a6e29790e69120d4
    ID             : 99e499a6bf998bf2
    Name           : GET /api/v1/healthz http send
    Kind           : Internal
    Start time     : 2026-07-13 15:50:23.018245012 +0000 UTC
    End time       : 2026-07-13 15:50:23.018251304 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #11
    Trace ID       : 73957477a4c9e5969adfeb882395dca4
    Parent ID      :
    ID             : a6e29790e69120d4
    Name           : GET /api/v1/healthz
    Kind           : Server
    Start time     : 2026-07-13 15:50:23.017542512 +0000 UTC
    End time       : 2026-07-13 15:50:23.018267387 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(127.0.0.1:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/healthz)
     -> http.url: Str(https://127.0.0.1:18443/api/v1/healthz)
     -> http.method: Str(GET)
     -> http.server_name: Str(127.0.0.1:18443)
     -> http.user_agent: Str(curl/8.7.1)
     -> net.peer.ip: Str(127.0.0.1)
     -> net.peer.port: Int(40292)
     -> http.route: Str(/api/v1/healthz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-13 15:50:17,367", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-13 15:50:20,754", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-13 15:50:21,283", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7cddb272b1944001aa008d411c9943cb", "trace_id": "b8eeb127cff4a06d9f51031353d9b175", "span_id": "31295df00196cdcb", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.348, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 15:50:21,652", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-be180ba7a81e49cbb0f3a0f8d93dd3bc", "trace_id": "4336fcfe4fcc2a9fcd523729f33c0c96", "span_id": "cc02a9e7e91a1e74"}
{"ts": "2026-07-13 15:50:21,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-be180ba7a81e49cbb0f3a0f8d93dd3bc", "trace_id": "4336fcfe4fcc2a9fcd523729f33c0c96", "span_id": "cc02a9e7e91a1e74"}
{"ts": "2026-07-13 15:50:21,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-be180ba7a81e49cbb0f3a0f8d93dd3bc", "trace_id": "4336fcfe4fcc2a9fcd523729f33c0c96", "span_id": "cc02a9e7e91a1e74"}
{"ts": "2026-07-13 15:50:21,676", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-be180ba7a81e49cbb0f3a0f8d93dd3bc", "trace_id": "4336fcfe4fcc2a9fcd523729f33c0c96", "span_id": "cc02a9e7e91a1e74", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 31.075, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 15:50:23,017", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-59444b0a3ff0458592af3e09ca2a6026", "trace_id": "73957477a4c9e5969adfeb882395dca4", "span_id": "a6e29790e69120d4", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.113, "client_addr": "127.0.0.1"}
```

## Proof M8.5 slice — FAILURE (2026-07-13T16:50:35Z)

- Failed step: `the BFF (cognic-proof-harness) did not become ready within 300s — check the harness pod logs (Settings fail-closed? Redis TLS? OIDC discovery?)`
- Attempt 4 exited 1 before Bars A-F and before any model call. The 795-line
  operator-held log has SHA-256
  `d799775970e7d7d22efe8eaef1b85e8aef225a3abb98abfd396916be0e326fc8`.
- Operator diagnosis: both BFF pods reached `Running` and logged application
  startup complete, but remained `0/1`; Kubernetes repeatedly requested the
  manifest's `/healthz` readiness path and received `404 Not Found`. The v1
  harness exposes no `/healthz` route. Step 0a had already passed the exact
  live access-token/ID-token claim split, so this was a BFF readiness-contract
  defect, not an OIDC realm regression.
- last API response (HTTP ):
```json
<no response captured>

```
- conversation.% chain rows (tail 10 — digest-only):
```
<none>
```
- conversations operational records (tail 6 — no plaintext):
```
<none>
```
- agent / dispatch / gateway reason markers:
```
<none captured>
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
<none>
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
<none>
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m16:45:01 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m16:45:01 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#           'It would help me if you could add...'            #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:43638 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:56582 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39764 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:60168 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:52032 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36342 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:37648 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:50416 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33398 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57548 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:58640 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:59794 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36488 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53876 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:45772 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:38776 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39970 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:44064 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47714 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:43216 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:37068 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57140 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47864 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:40874 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54158 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:58696 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55238 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51162 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:49500 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47462 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35072 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39550 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46948 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57394 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
<none>
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"7bce4f1c456137c5793796472083e8e7bea1c8f9a7bd78754c6f24b45fc4a085","refusal_reason":null,"registered_at":"2026-07-13T16:45:10.324639+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9cbb2f14cbf5bf8acf459721edffde397b9bb267102a1104d77f9c9fcaf81dc4","refusal_reason":null,"registered_at":"2026-07-13T16:45:10.587390+00:00","discovery_status":"unprobed"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-13T16:45:10.844400+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-13T16:45:11.093635+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-13T16:45:11.355727+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-13T16:45:11.612066+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-13T16:45:11.871136+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-13T16:45:12.116602+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-13T16:45:12.366195+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":9,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : 3d4c7144b2893c9d
    ID             : f4c89e7c7f33b4ad
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-13 16:50:23.691626637 +0000 UTC
    End time       : 2026-07-13 16:50:23.691654179 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #1
    Trace ID       : 6cc32c61303f752069c0f909c2e2be01
    Parent ID      : 3d4c7144b2893c9d
    ID             : 7ae25ff2cc80b417
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-13 16:50:23.691781012 +0000 UTC
    End time       : 2026-07-13 16:50:23.691788762 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #2
    Trace ID       : 6cc32c61303f752069c0f909c2e2be01
    Parent ID      : 3d4c7144b2893c9d
    ID             : b58fb5fdd67bd650
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-13 16:50:23.691829679 +0000 UTC
    End time       : 2026-07-13 16:50:23.691836804 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #3
    Trace ID       : 6cc32c61303f752069c0f909c2e2be01
    Parent ID      :
    ID             : 3d4c7144b2893c9d
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-13 16:50:23.667844262 +0000 UTC
    End time       : 2026-07-13 16:50:23.691889762 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.23:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.23:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.23:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(34696)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-13 16:45:09,402", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-13 16:45:12,853", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-13 16:45:13,273", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-273045be73af451dafdc5071badd9bb1", "trace_id": "493200775015c8f1e1a8c55c7f5b7185", "span_id": "7197a6986c8e0f73", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.028, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:13,672", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-46d0877d8ce3427a80a723b29a324949", "trace_id": "3ed48a889a4477ee20f8d3df2e865603", "span_id": "4d41f29bbae4c461"}
{"ts": "2026-07-13 16:45:13,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-46d0877d8ce3427a80a723b29a324949", "trace_id": "3ed48a889a4477ee20f8d3df2e865603", "span_id": "4d41f29bbae4c461"}
{"ts": "2026-07-13 16:45:13,697", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-46d0877d8ce3427a80a723b29a324949", "trace_id": "3ed48a889a4477ee20f8d3df2e865603", "span_id": "4d41f29bbae4c461"}
{"ts": "2026-07-13 16:45:13,698", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-46d0877d8ce3427a80a723b29a324949", "trace_id": "3ed48a889a4477ee20f8d3df2e865603", "span_id": "4d41f29bbae4c461", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 30.614, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:15,034", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e6043187eefc4f83b672555873192d58", "trace_id": "0411a077fed5209db9f5e4f07a4e489a", "span_id": "4ce340193d05bead", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.124, "client_addr": "127.0.0.1"}
{"ts": "2026-07-13 16:45:18,080", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c22f754d294748109b223905d3881d88", "trace_id": "309d21158cdb050df0921518c7f4744d", "span_id": "14d48442efcf1a50", "http_method": "GET", "http_path": "/api/v1/system/plugins", "http_has_query": true, "http_query_param_count": 1, "http_status_code": 200, "duration_ms": 1.01, "client_addr": "127.0.0.1"}
{"ts": "2026-07-13 16:45:18,191", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f2c9abbc781f42aabca628ba6a7c549f", "trace_id": "78599a6d57bbeef090cf45aa3d74457a", "span_id": "4c6642476e15a9e7", "http_method": "GET", "http_path": "/api/v1/system/plugins", "http_has_query": true, "http_query_param_count": 1, "http_status_code": 200, "duration_ms": 0.216, "client_addr": "127.0.0.1"}
{"ts": "2026-07-13 16:45:18,271", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2cf803e1d6fb47d6b07db2ca4287275f", "trace_id": "fda1a9fdd40de0ee249c1093c5b07d75", "span_id": "974f72082963727a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.124, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:23,661", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c455557ba0e8475fb39c931e893e5a7e", "trace_id": "72002a93b70b3a25014c97bce727c422", "span_id": "6ce891dd2c434b3d"}
{"ts": "2026-07-13 16:45:23,672", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c455557ba0e8475fb39c931e893e5a7e", "trace_id": "72002a93b70b3a25014c97bce727c422", "span_id": "6ce891dd2c434b3d"}
{"ts": "2026-07-13 16:45:23,683", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c455557ba0e8475fb39c931e893e5a7e", "trace_id": "72002a93b70b3a25014c97bce727c422", "span_id": "6ce891dd2c434b3d"}
{"ts": "2026-07-13 16:45:23,683", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c455557ba0e8475fb39c931e893e5a7e", "trace_id": "72002a93b70b3a25014c97bce727c422", "span_id": "6ce891dd2c434b3d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.911, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:33,270", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-03efb567c4394453bba8ca4764fe22e4", "trace_id": "c3c72cadda9135b08de26a2f8e984d5e", "span_id": "094d5dfe05682a29", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.107, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:33,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2afcc6e4e08b4153b5a8fe7648179db0", "trace_id": "5581823c4b53ba44b9e3440033853faf", "span_id": "fcf9de0e7f648ea8"}
{"ts": "2026-07-13 16:45:33,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2afcc6e4e08b4153b5a8fe7648179db0", "trace_id": "5581823c4b53ba44b9e3440033853faf", "span_id": "fcf9de0e7f648ea8"}
{"ts": "2026-07-13 16:45:33,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2afcc6e4e08b4153b5a8fe7648179db0", "trace_id": "5581823c4b53ba44b9e3440033853faf", "span_id": "fcf9de0e7f648ea8"}
{"ts": "2026-07-13 16:45:33,686", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2afcc6e4e08b4153b5a8fe7648179db0", "trace_id": "5581823c4b53ba44b9e3440033853faf", "span_id": "fcf9de0e7f648ea8", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.231, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:43,662", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9f0620b1bb2245b49e75675c555c339e", "trace_id": "7b583c0018bedc400774975574c7be0c", "span_id": "b4023cffe6b56c8e"}
{"ts": "2026-07-13 16:45:43,673", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9f0620b1bb2245b49e75675c555c339e", "trace_id": "7b583c0018bedc400774975574c7be0c", "span_id": "b4023cffe6b56c8e"}
{"ts": "2026-07-13 16:45:43,684", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9f0620b1bb2245b49e75675c555c339e", "trace_id": "7b583c0018bedc400774975574c7be0c", "span_id": "b4023cffe6b56c8e"}
{"ts": "2026-07-13 16:45:43,684", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9f0620b1bb2245b49e75675c555c339e", "trace_id": "7b583c0018bedc400774975574c7be0c", "span_id": "b4023cffe6b56c8e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.106, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:48,277", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-6294ddb162b146919d719b44f63d5d17", "trace_id": "364b635e0a0b5471a70505d08f0499fa", "span_id": "b421a75103375756", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.324, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:45:53,669", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-844bacd17f604a2fa57325ba27831893", "trace_id": "af5676ecab5842704eba4cdd9c2843b5", "span_id": "8a338a36344e9d3c"}
{"ts": "2026-07-13 16:45:53,680", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-844bacd17f604a2fa57325ba27831893", "trace_id": "af5676ecab5842704eba4cdd9c2843b5", "span_id": "8a338a36344e9d3c"}
{"ts": "2026-07-13 16:45:53,690", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-844bacd17f604a2fa57325ba27831893", "trace_id": "af5676ecab5842704eba4cdd9c2843b5", "span_id": "8a338a36344e9d3c"}
{"ts": "2026-07-13 16:45:53,690", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-844bacd17f604a2fa57325ba27831893", "trace_id": "af5676ecab5842704eba4cdd9c2843b5", "span_id": "8a338a36344e9d3c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.049, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:03,272", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2af61fb32df843a8ba104f8205cb3595", "trace_id": "54409506b503195220c9e43dfcd088be", "span_id": "f631890db9d5e7cc", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.104, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:03,666", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5194579f2bcc42688970ec2f354d6f80", "trace_id": "bdd5f13ec60dc03f45457b8db506953d", "span_id": "2569d4e1e9d14d66"}
{"ts": "2026-07-13 16:46:03,677", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5194579f2bcc42688970ec2f354d6f80", "trace_id": "bdd5f13ec60dc03f45457b8db506953d", "span_id": "2569d4e1e9d14d66"}
{"ts": "2026-07-13 16:46:03,688", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5194579f2bcc42688970ec2f354d6f80", "trace_id": "bdd5f13ec60dc03f45457b8db506953d", "span_id": "2569d4e1e9d14d66"}
{"ts": "2026-07-13 16:46:03,688", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5194579f2bcc42688970ec2f354d6f80", "trace_id": "bdd5f13ec60dc03f45457b8db506953d", "span_id": "2569d4e1e9d14d66", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.728, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:13,673", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9d711cbabc78459a8bc2252090bcd334", "trace_id": "ad51bcabcc1c541e9f6e3d9aeae2a726", "span_id": "85f25a174a3af276"}
{"ts": "2026-07-13 16:46:13,683", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9d711cbabc78459a8bc2252090bcd334", "trace_id": "ad51bcabcc1c541e9f6e3d9aeae2a726", "span_id": "85f25a174a3af276"}
{"ts": "2026-07-13 16:46:13,693", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9d711cbabc78459a8bc2252090bcd334", "trace_id": "ad51bcabcc1c541e9f6e3d9aeae2a726", "span_id": "85f25a174a3af276"}
{"ts": "2026-07-13 16:46:13,694", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9d711cbabc78459a8bc2252090bcd334", "trace_id": "ad51bcabcc1c541e9f6e3d9aeae2a726", "span_id": "85f25a174a3af276", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.866, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:18,276", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e6a733a7d5464604b10f64c6452b920f", "trace_id": "824709e7a023b4603346b48d922211f6", "span_id": "6524fc3ce8ddfc3f", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.224, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:23,669", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-621b9fcc7d02439ca3ad0ff37ba44101", "trace_id": "bd2206875a21322c22e4567d74ff0dba", "span_id": "2eefac3d1572dc3d"}
{"ts": "2026-07-13 16:46:23,681", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-621b9fcc7d02439ca3ad0ff37ba44101", "trace_id": "bd2206875a21322c22e4567d74ff0dba", "span_id": "2eefac3d1572dc3d"}
{"ts": "2026-07-13 16:46:23,690", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-621b9fcc7d02439ca3ad0ff37ba44101", "trace_id": "bd2206875a21322c22e4567d74ff0dba", "span_id": "2eefac3d1572dc3d"}
{"ts": "2026-07-13 16:46:23,691", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-621b9fcc7d02439ca3ad0ff37ba44101", "trace_id": "bd2206875a21322c22e4567d74ff0dba", "span_id": "2eefac3d1572dc3d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 29.638, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:33,272", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-63b33d1fc81d48a9a779867f7b5c6c66", "trace_id": "29026915adfda2412bd5b7f60503ef97", "span_id": "a6bcb7b7cdae863d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.116, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:33,666", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-321a691200b449a0bd904d78e021286e", "trace_id": "090d460aac5a01f366c68a3ffe7cbf1c", "span_id": "af3213ae1df555bf"}
{"ts": "2026-07-13 16:46:33,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-321a691200b449a0bd904d78e021286e", "trace_id": "090d460aac5a01f366c68a3ffe7cbf1c", "span_id": "af3213ae1df555bf"}
{"ts": "2026-07-13 16:46:33,687", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-321a691200b449a0bd904d78e021286e", "trace_id": "090d460aac5a01f366c68a3ffe7cbf1c", "span_id": "af3213ae1df555bf"}
{"ts": "2026-07-13 16:46:33,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-321a691200b449a0bd904d78e021286e", "trace_id": "090d460aac5a01f366c68a3ffe7cbf1c", "span_id": "af3213ae1df555bf", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.062, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:43,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-34e367ae7e394aafbbe5593209e08ca0", "trace_id": "86fad5af4e17b05bc8ad07477cffb50c", "span_id": "73f0cdfc55118908"}
{"ts": "2026-07-13 16:46:43,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-34e367ae7e394aafbbe5593209e08ca0", "trace_id": "86fad5af4e17b05bc8ad07477cffb50c", "span_id": "73f0cdfc55118908"}
{"ts": "2026-07-13 16:46:43,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-34e367ae7e394aafbbe5593209e08ca0", "trace_id": "86fad5af4e17b05bc8ad07477cffb50c", "span_id": "73f0cdfc55118908"}
{"ts": "2026-07-13 16:46:43,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-34e367ae7e394aafbbe5593209e08ca0", "trace_id": "86fad5af4e17b05bc8ad07477cffb50c", "span_id": "73f0cdfc55118908", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.873, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:48,277", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c68506d7d03c4f0fbc44885183e4fd3a", "trace_id": "cb236563400fc6174a47bced081f36d9", "span_id": "bf6521e82e21db5e", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.216, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:46:53,666", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2941a246a80140d386ca68dac1e7c81a", "trace_id": "4328a4b2eda3a4ff5564c6d1c414ee07", "span_id": "157289fd7dd62e30"}
{"ts": "2026-07-13 16:46:53,677", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2941a246a80140d386ca68dac1e7c81a", "trace_id": "4328a4b2eda3a4ff5564c6d1c414ee07", "span_id": "157289fd7dd62e30"}
{"ts": "2026-07-13 16:46:53,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2941a246a80140d386ca68dac1e7c81a", "trace_id": "4328a4b2eda3a4ff5564c6d1c414ee07", "span_id": "157289fd7dd62e30"}
{"ts": "2026-07-13 16:46:53,686", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2941a246a80140d386ca68dac1e7c81a", "trace_id": "4328a4b2eda3a4ff5564c6d1c414ee07", "span_id": "157289fd7dd62e30", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.399, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:03,274", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8a32872db8b74f879cc18c691ecfc9c7", "trace_id": "72df257149a36354a4bbd84638de894e", "span_id": "d95f9cba9c80178e", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.116, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:03,675", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4663d7facd334650aae5e9070431f74d", "trace_id": "95d1c5af57e9f34c14fbfe69dcd6c7ca", "span_id": "a19a9a724cfc4f4b"}
{"ts": "2026-07-13 16:47:03,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4663d7facd334650aae5e9070431f74d", "trace_id": "95d1c5af57e9f34c14fbfe69dcd6c7ca", "span_id": "a19a9a724cfc4f4b"}
{"ts": "2026-07-13 16:47:03,695", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4663d7facd334650aae5e9070431f74d", "trace_id": "95d1c5af57e9f34c14fbfe69dcd6c7ca", "span_id": "a19a9a724cfc4f4b"}
{"ts": "2026-07-13 16:47:03,695", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4663d7facd334650aae5e9070431f74d", "trace_id": "95d1c5af57e9f34c14fbfe69dcd6c7ca", "span_id": "a19a9a724cfc4f4b", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 30.164, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:13,667", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-94f613324b5a43e580c7165b226b8a74", "trace_id": "50dfb2ddefddcb5d73d5ff95839127d9", "span_id": "7fd28b49b9d497e6"}
{"ts": "2026-07-13 16:47:13,678", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-94f613324b5a43e580c7165b226b8a74", "trace_id": "50dfb2ddefddcb5d73d5ff95839127d9", "span_id": "7fd28b49b9d497e6"}
{"ts": "2026-07-13 16:47:13,688", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-94f613324b5a43e580c7165b226b8a74", "trace_id": "50dfb2ddefddcb5d73d5ff95839127d9", "span_id": "7fd28b49b9d497e6"}
{"ts": "2026-07-13 16:47:13,688", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-94f613324b5a43e580c7165b226b8a74", "trace_id": "50dfb2ddefddcb5d73d5ff95839127d9", "span_id": "7fd28b49b9d497e6", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.436, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:18,279", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7589105500b941e6ab4d3a85fb30d95b", "trace_id": "998ca9b7ab8b5c1479f1e13f8ae29818", "span_id": "9fdd42ae41c110bd", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.204, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:23,667", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-125e297d06ba4eab9e25438d55fd85bc", "trace_id": "6b90c2479236afb534973463a7264c71", "span_id": "b21bce8e1d01cce9"}
{"ts": "2026-07-13 16:47:23,678", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-125e297d06ba4eab9e25438d55fd85bc", "trace_id": "6b90c2479236afb534973463a7264c71", "span_id": "b21bce8e1d01cce9"}
{"ts": "2026-07-13 16:47:23,688", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-125e297d06ba4eab9e25438d55fd85bc", "trace_id": "6b90c2479236afb534973463a7264c71", "span_id": "b21bce8e1d01cce9"}
{"ts": "2026-07-13 16:47:23,688", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-125e297d06ba4eab9e25438d55fd85bc", "trace_id": "6b90c2479236afb534973463a7264c71", "span_id": "b21bce8e1d01cce9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.236, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:33,274", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8bdb909bd35646d791962111e446c39b", "trace_id": "436da823a11f6d30d2787479e229e7fb", "span_id": "aaf53fe71b547d39", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.118, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:33,670", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a71e61d0b6414c8b8aeefa44cc7c13a9", "trace_id": "b4cbe98d5d1b8cdfc4fc348e326796a4", "span_id": "5974987ae2a31608"}
{"ts": "2026-07-13 16:47:33,682", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a71e61d0b6414c8b8aeefa44cc7c13a9", "trace_id": "b4cbe98d5d1b8cdfc4fc348e326796a4", "span_id": "5974987ae2a31608"}
{"ts": "2026-07-13 16:47:33,691", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a71e61d0b6414c8b8aeefa44cc7c13a9", "trace_id": "b4cbe98d5d1b8cdfc4fc348e326796a4", "span_id": "5974987ae2a31608"}
{"ts": "2026-07-13 16:47:33,692", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a71e61d0b6414c8b8aeefa44cc7c13a9", "trace_id": "b4cbe98d5d1b8cdfc4fc348e326796a4", "span_id": "5974987ae2a31608", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.581, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:43,667", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-46a42bee1bd34a55bda65c91315531e0", "trace_id": "d156dfec05f29d0aa8224424f2131db2", "span_id": "66deae7ae47d6ebd"}
{"ts": "2026-07-13 16:47:43,678", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-46a42bee1bd34a55bda65c91315531e0", "trace_id": "d156dfec05f29d0aa8224424f2131db2", "span_id": "66deae7ae47d6ebd"}
{"ts": "2026-07-13 16:47:43,687", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-46a42bee1bd34a55bda65c91315531e0", "trace_id": "d156dfec05f29d0aa8224424f2131db2", "span_id": "66deae7ae47d6ebd"}
{"ts": "2026-07-13 16:47:43,688", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-46a42bee1bd34a55bda65c91315531e0", "trace_id": "d156dfec05f29d0aa8224424f2131db2", "span_id": "66deae7ae47d6ebd", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.326, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:48,279", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a299ed2f2a364d60a867522d57659b84", "trace_id": "e098a9f01ac81b4099ec2de5002911ca", "span_id": "b09370595af8e400", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.205, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:47:53,670", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c064b55df9ac49728b6f4d441a2a733a", "trace_id": "f4a9b77cec71d8b4efc16ad6a9b33e55", "span_id": "248ca7dc8dab21d4"}
{"ts": "2026-07-13 16:47:53,681", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c064b55df9ac49728b6f4d441a2a733a", "trace_id": "f4a9b77cec71d8b4efc16ad6a9b33e55", "span_id": "248ca7dc8dab21d4"}
{"ts": "2026-07-13 16:47:53,690", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c064b55df9ac49728b6f4d441a2a733a", "trace_id": "f4a9b77cec71d8b4efc16ad6a9b33e55", "span_id": "248ca7dc8dab21d4"}
{"ts": "2026-07-13 16:47:53,691", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c064b55df9ac49728b6f4d441a2a733a", "trace_id": "f4a9b77cec71d8b4efc16ad6a9b33e55", "span_id": "248ca7dc8dab21d4", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.245, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:03,275", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e392eb2145c5426690e3dbcfc31331c6", "trace_id": "38a396c1b865d42fef6f80b95def1ad9", "span_id": "cd9580c20ec08d77", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.113, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:03,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e68a2c214bcd4211a3bce02bc685cda2", "trace_id": "89a1a9b76cb3cbfdc8a8f07d33ca88c3", "span_id": "1bc3592e78c75d95"}
{"ts": "2026-07-13 16:48:03,675", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e68a2c214bcd4211a3bce02bc685cda2", "trace_id": "89a1a9b76cb3cbfdc8a8f07d33ca88c3", "span_id": "1bc3592e78c75d95"}
{"ts": "2026-07-13 16:48:03,685", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e68a2c214bcd4211a3bce02bc685cda2", "trace_id": "89a1a9b76cb3cbfdc8a8f07d33ca88c3", "span_id": "1bc3592e78c75d95"}
{"ts": "2026-07-13 16:48:03,686", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e68a2c214bcd4211a3bce02bc685cda2", "trace_id": "89a1a9b76cb3cbfdc8a8f07d33ca88c3", "span_id": "1bc3592e78c75d95", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.347, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:13,666", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-16725cc6cbf24aee8dc7363f63b7fd09", "trace_id": "044d5d431feadc96c7983bc3071a01e2", "span_id": "16db109d1bd65e00"}
{"ts": "2026-07-13 16:48:13,677", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-16725cc6cbf24aee8dc7363f63b7fd09", "trace_id": "044d5d431feadc96c7983bc3071a01e2", "span_id": "16db109d1bd65e00"}
{"ts": "2026-07-13 16:48:13,687", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-16725cc6cbf24aee8dc7363f63b7fd09", "trace_id": "044d5d431feadc96c7983bc3071a01e2", "span_id": "16db109d1bd65e00"}
{"ts": "2026-07-13 16:48:13,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-16725cc6cbf24aee8dc7363f63b7fd09", "trace_id": "044d5d431feadc96c7983bc3071a01e2", "span_id": "16db109d1bd65e00", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.701, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:18,280", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-92e2cfaeb411494dabc96b5d02e3f087", "trace_id": "3bb87c8a16eb6c7c8d9b6de55c7b2dff", "span_id": "61fe6d04404b5ede", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.248, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:23,663", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-906122cc3e824c54b1f1377e4a4909cd", "trace_id": "e7501fec1864048fb62eead243fb6378", "span_id": "8e759d48897934fb"}
{"ts": "2026-07-13 16:48:23,674", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-906122cc3e824c54b1f1377e4a4909cd", "trace_id": "e7501fec1864048fb62eead243fb6378", "span_id": "8e759d48897934fb"}
{"ts": "2026-07-13 16:48:23,685", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-906122cc3e824c54b1f1377e4a4909cd", "trace_id": "e7501fec1864048fb62eead243fb6378", "span_id": "8e759d48897934fb"}
{"ts": "2026-07-13 16:48:23,686", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-906122cc3e824c54b1f1377e4a4909cd", "trace_id": "e7501fec1864048fb62eead243fb6378", "span_id": "8e759d48897934fb", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.332, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:33,270", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fa66522e605f4e8d88d4658afd20b9a8", "trace_id": "9367a30b06758fa28cae8c576235c2c1", "span_id": "42f8a8e7daa9c04a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.125, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:33,667", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fde04c30e77c4b87b69d5d6086007740", "trace_id": "463421013e57c76c32cb1f7905519b86", "span_id": "4eaec0d8e6e570a0"}
{"ts": "2026-07-13 16:48:33,678", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fde04c30e77c4b87b69d5d6086007740", "trace_id": "463421013e57c76c32cb1f7905519b86", "span_id": "4eaec0d8e6e570a0"}
{"ts": "2026-07-13 16:48:33,688", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fde04c30e77c4b87b69d5d6086007740", "trace_id": "463421013e57c76c32cb1f7905519b86", "span_id": "4eaec0d8e6e570a0"}
{"ts": "2026-07-13 16:48:33,688", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fde04c30e77c4b87b69d5d6086007740", "trace_id": "463421013e57c76c32cb1f7905519b86", "span_id": "4eaec0d8e6e570a0", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.703, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:43,660", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1e86da95e898456ab684c497ceab98ef", "trace_id": "c5266b6dd95da70f3ebd437450ca21cb", "span_id": "65e3e4052f4ecc60"}
{"ts": "2026-07-13 16:48:43,671", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1e86da95e898456ab684c497ceab98ef", "trace_id": "c5266b6dd95da70f3ebd437450ca21cb", "span_id": "65e3e4052f4ecc60"}
{"ts": "2026-07-13 16:48:43,681", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1e86da95e898456ab684c497ceab98ef", "trace_id": "c5266b6dd95da70f3ebd437450ca21cb", "span_id": "65e3e4052f4ecc60"}
{"ts": "2026-07-13 16:48:43,682", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1e86da95e898456ab684c497ceab98ef", "trace_id": "c5266b6dd95da70f3ebd437450ca21cb", "span_id": "65e3e4052f4ecc60", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.834, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:48,282", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1fc33d6e537e419db36727fe1e854a55", "trace_id": "a730f921a58e37621f0e53f9b23bad1f", "span_id": "19244d833c67fa33", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.215, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:48:53,659", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-848c6de2d3a14d46b23eb82cb97eb5af", "trace_id": "fffa56fec965ec018cdbb2f6f8c25933", "span_id": "0dc71e864101584d"}
{"ts": "2026-07-13 16:48:53,670", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-848c6de2d3a14d46b23eb82cb97eb5af", "trace_id": "fffa56fec965ec018cdbb2f6f8c25933", "span_id": "0dc71e864101584d"}
{"ts": "2026-07-13 16:48:53,679", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-848c6de2d3a14d46b23eb82cb97eb5af", "trace_id": "fffa56fec965ec018cdbb2f6f8c25933", "span_id": "0dc71e864101584d"}
{"ts": "2026-07-13 16:48:53,680", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-848c6de2d3a14d46b23eb82cb97eb5af", "trace_id": "fffa56fec965ec018cdbb2f6f8c25933", "span_id": "0dc71e864101584d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.157, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:03,276", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-204287bd9e4e4a81b041063c557627f9", "trace_id": "4e20b2814a1f42acd345419f9e26903b", "span_id": "ec82a485cb41099c", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.109, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:03,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-02e98f178e5449bb9ae5a6bba43e6044", "trace_id": "12b667a549d1b04dea61a98ede1f83ff", "span_id": "cb17c891069625eb"}
{"ts": "2026-07-13 16:49:03,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-02e98f178e5449bb9ae5a6bba43e6044", "trace_id": "12b667a549d1b04dea61a98ede1f83ff", "span_id": "cb17c891069625eb"}
{"ts": "2026-07-13 16:49:03,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-02e98f178e5449bb9ae5a6bba43e6044", "trace_id": "12b667a549d1b04dea61a98ede1f83ff", "span_id": "cb17c891069625eb"}
{"ts": "2026-07-13 16:49:03,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-02e98f178e5449bb9ae5a6bba43e6044", "trace_id": "12b667a549d1b04dea61a98ede1f83ff", "span_id": "cb17c891069625eb", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.036, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:13,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3e7b702fdbe84f32800e39f08d88566d", "trace_id": "c8c2c0727f88f119271adb71bcd18f85", "span_id": "2df667f41a31a699"}
{"ts": "2026-07-13 16:49:13,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3e7b702fdbe84f32800e39f08d88566d", "trace_id": "c8c2c0727f88f119271adb71bcd18f85", "span_id": "2df667f41a31a699"}
{"ts": "2026-07-13 16:49:13,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3e7b702fdbe84f32800e39f08d88566d", "trace_id": "c8c2c0727f88f119271adb71bcd18f85", "span_id": "2df667f41a31a699"}
{"ts": "2026-07-13 16:49:13,686", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3e7b702fdbe84f32800e39f08d88566d", "trace_id": "c8c2c0727f88f119271adb71bcd18f85", "span_id": "2df667f41a31a699", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.447, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:18,280", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-838c10f8252e42a6b812acfe28ef8fdd", "trace_id": "5ceb0d5bf2c54ac01ca7882cc7b1f5f6", "span_id": "80b551f3c82187d4", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.204, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:23,667", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f4b96e1f93f147adae5cf2de44a75288", "trace_id": "7b0b2922ba1b86c68a40919d4f02a315", "span_id": "f5629a3ef55d91e5"}
{"ts": "2026-07-13 16:49:23,677", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f4b96e1f93f147adae5cf2de44a75288", "trace_id": "7b0b2922ba1b86c68a40919d4f02a315", "span_id": "f5629a3ef55d91e5"}
{"ts": "2026-07-13 16:49:23,687", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f4b96e1f93f147adae5cf2de44a75288", "trace_id": "7b0b2922ba1b86c68a40919d4f02a315", "span_id": "f5629a3ef55d91e5"}
{"ts": "2026-07-13 16:49:23,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f4b96e1f93f147adae5cf2de44a75288", "trace_id": "7b0b2922ba1b86c68a40919d4f02a315", "span_id": "f5629a3ef55d91e5", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.347, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:33,278", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e7e6c8dcb0b54249ac844c2d4872ada8", "trace_id": "324e1c115ff34fa2a4d2c01e5155901a", "span_id": "6a65d84640888f7a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.127, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:33,666", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3be40f659e6d420da16b9c4d26cc1158", "trace_id": "f1795244c86d6f863443c94ccb6584c9", "span_id": "21ab0234b71c8704"}
{"ts": "2026-07-13 16:49:33,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3be40f659e6d420da16b9c4d26cc1158", "trace_id": "f1795244c86d6f863443c94ccb6584c9", "span_id": "21ab0234b71c8704"}
{"ts": "2026-07-13 16:49:33,687", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3be40f659e6d420da16b9c4d26cc1158", "trace_id": "f1795244c86d6f863443c94ccb6584c9", "span_id": "21ab0234b71c8704"}
{"ts": "2026-07-13 16:49:33,688", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3be40f659e6d420da16b9c4d26cc1158", "trace_id": "f1795244c86d6f863443c94ccb6584c9", "span_id": "21ab0234b71c8704", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.615, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:43,665", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-022b649436c746bda7f8df6091e6e0f0", "trace_id": "2fa710dbbabe10366a15b51c68d06e7c", "span_id": "b56eee049a6d0be9"}
{"ts": "2026-07-13 16:49:43,676", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-022b649436c746bda7f8df6091e6e0f0", "trace_id": "2fa710dbbabe10366a15b51c68d06e7c", "span_id": "b56eee049a6d0be9"}
{"ts": "2026-07-13 16:49:43,686", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-022b649436c746bda7f8df6091e6e0f0", "trace_id": "2fa710dbbabe10366a15b51c68d06e7c", "span_id": "b56eee049a6d0be9"}
{"ts": "2026-07-13 16:49:43,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-022b649436c746bda7f8df6091e6e0f0", "trace_id": "2fa710dbbabe10366a15b51c68d06e7c", "span_id": "b56eee049a6d0be9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.03, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:48,285", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9b96047de0784570a33a14a2a4efd9c9", "trace_id": "b7d9355c471cbc4db6bf81671ccd08c6", "span_id": "634ffd3d957c5cab", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.256, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:49:53,667", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-abe880254fa8494a9ea267dadb5aaa33", "trace_id": "6533cf02b5fc56780142b0981020ae4a", "span_id": "af7bb6a47a72de28"}
{"ts": "2026-07-13 16:49:53,679", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-abe880254fa8494a9ea267dadb5aaa33", "trace_id": "6533cf02b5fc56780142b0981020ae4a", "span_id": "af7bb6a47a72de28"}
{"ts": "2026-07-13 16:49:53,689", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-abe880254fa8494a9ea267dadb5aaa33", "trace_id": "6533cf02b5fc56780142b0981020ae4a", "span_id": "af7bb6a47a72de28"}
{"ts": "2026-07-13 16:49:53,690", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-abe880254fa8494a9ea267dadb5aaa33", "trace_id": "6533cf02b5fc56780142b0981020ae4a", "span_id": "af7bb6a47a72de28", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.15, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:03,278", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4d579220fd9d4a7e839e565632880174", "trace_id": "05045ccdd0734f574eb610063f9c2be2", "span_id": "8c73bfbcca10782d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.173, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:03,671", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d78f8c7a91b2442bbbf6bff9af7e5f3e", "trace_id": "2f35c71dab1a594878859032a8f615a8", "span_id": "ba0ece61bfb44faa"}
{"ts": "2026-07-13 16:50:03,681", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d78f8c7a91b2442bbbf6bff9af7e5f3e", "trace_id": "2f35c71dab1a594878859032a8f615a8", "span_id": "ba0ece61bfb44faa"}
{"ts": "2026-07-13 16:50:03,691", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d78f8c7a91b2442bbbf6bff9af7e5f3e", "trace_id": "2f35c71dab1a594878859032a8f615a8", "span_id": "ba0ece61bfb44faa"}
{"ts": "2026-07-13 16:50:03,692", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d78f8c7a91b2442bbbf6bff9af7e5f3e", "trace_id": "2f35c71dab1a594878859032a8f615a8", "span_id": "ba0ece61bfb44faa", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.4, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:13,672", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1fa207bbd0b44633962f29c0bbe1d42d", "trace_id": "14473f62e35b33821c83a972447abb9b", "span_id": "20f1cf82e30f8c68"}
{"ts": "2026-07-13 16:50:13,682", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1fa207bbd0b44633962f29c0bbe1d42d", "trace_id": "14473f62e35b33821c83a972447abb9b", "span_id": "20f1cf82e30f8c68"}
{"ts": "2026-07-13 16:50:13,692", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1fa207bbd0b44633962f29c0bbe1d42d", "trace_id": "14473f62e35b33821c83a972447abb9b", "span_id": "20f1cf82e30f8c68"}
{"ts": "2026-07-13 16:50:13,692", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1fa207bbd0b44633962f29c0bbe1d42d", "trace_id": "14473f62e35b33821c83a972447abb9b", "span_id": "20f1cf82e30f8c68", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.278, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:18,285", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7a7149c4c45b4532915e1a32e994a1f2", "trace_id": "69e90187ebcf139b05ddbc3c58775d93", "span_id": "1d4a8a483d628cf6", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.236, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:23,671", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ab6c44607319497fac5d13aabfbcae5f", "trace_id": "6cc32c61303f752069c0f909c2e2be01", "span_id": "3d4c7144b2893c9d"}
{"ts": "2026-07-13 16:50:23,681", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ab6c44607319497fac5d13aabfbcae5f", "trace_id": "6cc32c61303f752069c0f909c2e2be01", "span_id": "3d4c7144b2893c9d"}
{"ts": "2026-07-13 16:50:23,691", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ab6c44607319497fac5d13aabfbcae5f", "trace_id": "6cc32c61303f752069c0f909c2e2be01", "span_id": "3d4c7144b2893c9d"}
{"ts": "2026-07-13 16:50:23,691", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ab6c44607319497fac5d13aabfbcae5f", "trace_id": "6cc32c61303f752069c0f909c2e2be01", "span_id": "3d4c7144b2893c9d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.42, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:33,283", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1ccbaba746da4511b0d93d7ae7e8199b", "trace_id": "7f8ee26b68e1e4be3a4075df90ba563f", "span_id": "56c88938016af94d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.286, "client_addr": "10.244.0.1"}
{"ts": "2026-07-13 16:50:33,669", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a69cb2ab911f4485bab3c8da6a7d37ca", "trace_id": "3eee415e0ee5b31df8317d67eac5b114", "span_id": "504ba0719adc8779"}
{"ts": "2026-07-13 16:50:33,679", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a69cb2ab911f4485bab3c8da6a7d37ca", "trace_id": "3eee415e0ee5b31df8317d67eac5b114", "span_id": "504ba0719adc8779"}
{"ts": "2026-07-13 16:50:33,689", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a69cb2ab911f4485bab3c8da6a7d37ca", "trace_id": "3eee415e0ee5b31df8317d67eac5b114", "span_id": "504ba0719adc8779"}
{"ts": "2026-07-13 16:50:33,690", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a69cb2ab911f4485bab3c8da6a7d37ca", "trace_id": "3eee415e0ee5b31df8317d67eac5b114", "span_id": "504ba0719adc8779", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.477, "client_addr": "10.244.0.1"}
```

## Proof M8.5 slice — AgentOS rollout FAILURE (2026-07-14T00:51:13Z)

- Failed step: `rel-agentos pod did not become Ready within 600s`
- rel-agentos deploy/pods (-o wide):
```
error: selectors and the all flag cannot be used when passing resource/name arguments
```
- rel-agentos deployment describe:
```
Name:                   rel-agentos
Namespace:              cognic-proofm85c
CreationTimestamp:      Tue, 14 Jul 2026 05:40:41 +0500
Labels:                 app.kubernetes.io/instance=rel
                        app.kubernetes.io/managed-by=Helm
                        app.kubernetes.io/name=agentos
                        app.kubernetes.io/part-of=cognic-agentos
                        helm.sh/chart=agentos-0.1.0
Annotations:            deployment.kubernetes.io/revision: 5
                        meta.helm.sh/release-name: rel
                        meta.helm.sh/release-namespace: cognic-proofm85c
Selector:               app.kubernetes.io/instance=rel,app.kubernetes.io/name=agentos
Replicas:               1 desired | 1 updated | 1 total | 1 available | 0 unavailable
StrategyType:           RollingUpdate
MinReadySeconds:        0
RollingUpdateStrategy:  25% max unavailable, 25% max surge
Pod Template:
  Labels:           app.kubernetes.io/instance=rel
                    app.kubernetes.io/name=agentos
  Annotations:      kubectl.kubernetes.io/restartedAt: 2026-07-14T05:41:02+05:00
  Service Account:  rel-agentos
  Init Containers:
   broker-share-perms:
    Image:      busybox:1.36
    Port:       <none>
    Host Port:  <none>
    Command:
      sh
      -c
      chmod 1777 /var/lib/cognic-proof-m85c-broker && chgrp 65534 /var/run/docker.sock && chmod 0660 /var/run/docker.sock
    Environment:
      COGNIC_ALLOW_EXTERNAL_LLM:         true
      COGNIC_POLICY_MODE:                cloud_openai
      COGNIC_ALLOWED_PROVIDERS:          openai
      COGNIC_LITELLM_MASTER_KEY:         vault://secret/cognic/proof-m85c/litellm
      COGNIC_CONVERSATION_CLAIM_TTL_S:   600
      COGNIC_AGENT_RUN_TOKEN_BUDGET:     60000
      COGNIC_AGENT_RUN_WALL_CLOCK_S:     300
      COGNIC_APPROVAL_FOUR_EYES_TTL_S:   1800
      COGNIC_APPROVAL_SINGLE_TTL_S:      1800
      COGNIC_PROOF_M85C_OIDC_ISSUER:     https://cognic-proof-keycloak:8443/realms/proof-m85c
      COGNIC_PROOF_M85C_OIDC_CA_BUNDLE:  /etc/proof-ca/proof-ca.pem
    Mounts:
      /var/lib/cognic-proof-m85c-broker from broker-share (rw)
      /var/run/docker.sock from docker-sock (rw)
  Containers:
   agentos:
    Image:           cognic-agentos:proofm85c
    Port:            8443/TCP
    Host Port:       0/TCP
    SeccompProfile:  RuntimeDefault
    Limits:
      cpu:     2
      memory:  2Gi
    Requests:
      cpu:      250m
      memory:   512Mi
    Liveness:   http-get https://:http/api/v1/healthz delay=0s timeout=5s period=15s #success=1 #failure=3
    Readiness:  http-get https://:http/api/v1/readyz delay=0s timeout=5s period=10s #success=1 #failure=3
    Startup:    http-get https://:http/api/v1/healthz delay=0s timeout=1s period=5s #success=1 #failure=30
    Environment Variables from:
      rel-agentos-config  ConfigMap  Optional: false
    Environment:
      TMPDIR:                            /var/lib/cognic-proof-m85c-broker
      COGNIC_PORT:                       8443
      COGNIC_DATABASE_URL:               <set to the key 'COGNIC_DATABASE_URL' in secret 'rel-agentos-secrets'>  Optional: false
      COGNIC_VAULT_TOKEN:                <set to the key 'COGNIC_VAULT_TOKEN' in secret 'rel-agentos-secrets'>   Optional: false
      COGNIC_ALLOW_EXTERNAL_LLM:         true
      COGNIC_POLICY_MODE:                cloud_openai
      COGNIC_ALLOWED_PROVIDERS:          openai
      COGNIC_LITELLM_MASTER_KEY:         vault://secret/cognic/proof-m85c/litellm
      COGNIC_CONVERSATION_CLAIM_TTL_S:   600
      COGNIC_AGENT_RUN_TOKEN_BUDGET:     60000
      COGNIC_AGENT_RUN_WALL_CLOCK_S:     300
      COGNIC_APPROVAL_FOUR_EYES_TTL_S:   1800
      COGNIC_APPROVAL_SINGLE_TTL_S:      1800
      COGNIC_PROOF_M85C_OIDC_ISSUER:     https://cognic-proof-keycloak:8443/realms/proof-m85c
      COGNIC_PROOF_M85C_OIDC_CA_BUNDLE:  /etc/proof-ca/proof-ca.pem
    Mounts:
      /app/infra/litellm from litellm-config (ro)
      /etc/agentos-tls from agentos-tls (ro)
      /etc/proof-ca from proof-ca (ro)
      /run/cognic/query-context from query-context (ro)
      /tmp from tmp (rw)
      /var/lib/cognic-agentos/object-store from object-store (rw)
      /var/lib/cognic-proof-m85c-broker from broker-share (rw)
      /var/lib/cognic/model-artifacts from model-artifacts (rw)
      /var/run/docker.sock from docker-sock (rw)
  Volumes:
   docker-sock:
    Type:          HostPath (bare host directory volume)
    Path:          /var/run/docker.sock
    HostPathType:
   broker-share:
    Type:          HostPath (bare host directory volume)
    Path:          /var/lib/cognic-proof-m85c-broker
    HostPathType:  DirectoryOrCreate
   query-context:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-query-context
    Optional:    false
   agentos-tls:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-agentos-tls
    Optional:    false
   proof-ca:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-ca
    Optional:    false
   litellm-config:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      rel-agentos-litellm
    Optional:  false
   tmp:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  256Mi
   object-store:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  5Gi
   model-artifacts:
    Type:          EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:     5Gi
  Node-Selectors:  <none>
  Tolerations:     <none>
Conditions:
  Type           Status  Reason
  ----           ------  ------
  Available      True    MinimumReplicasAvailable
  Progressing    True    NewReplicaSetAvailable
OldReplicaSets:  rel-agentos-577f67f98b (0/0 replicas created), rel-agentos-575dfb5f9f (0/0 replicas created), rel-agentos-5d59c8cfb8 (0/0 replicas created), rel-agentos-bf64f5589 (0/0 replicas created)
NewReplicaSet:   rel-agentos-c796b8c9f (1/1 replicas created)
Events:
  Type    Reason             Age   From                   Message
  ----    ------             ----  ----                   -------
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled up replica set rel-agentos-577f67f98b from 0 to 1
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled up replica set rel-agentos-bf64f5589 from 0 to 1
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled down replica set rel-agentos-577f67f98b from 1 to 0
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled up replica set rel-agentos-575dfb5f9f from 0 to 1
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled down replica set rel-agentos-575dfb5f9f from 1 to 0
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled up replica set rel-agentos-5d59c8cfb8 from 0 to 1
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled down replica set rel-agentos-5d59c8cfb8 from 1 to 0
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled up replica set rel-agentos-c796b8c9f from 0 to 1
  Normal  ScalingReplicaSet  10m   deployment-controller  Scaled down replica set rel-agentos-bf64f5589 from 1 to 0
```
- rel-agentos pod describe:
```
Name:             rel-agentos-c796b8c9f-xg47s
Namespace:        cognic-proofm85c
Priority:         0
Service Account:  rel-agentos
Node:             cognic-proofm85c-control-plane/172.27.0.2
Start Time:       Tue, 14 Jul 2026 05:41:02 +0500
Labels:           app.kubernetes.io/instance=rel
                  app.kubernetes.io/name=agentos
                  pod-template-hash=c796b8c9f
Annotations:      kubectl.kubernetes.io/restartedAt: 2026-07-14T05:41:02+05:00
Status:           Running
IP:               10.244.0.23
IPs:
  IP:           10.244.0.23
Controlled By:  ReplicaSet/rel-agentos-c796b8c9f
Init Containers:
  broker-share-perms:
    Container ID:  containerd://08ceb1273af31e0e9cf5d5712609efa2842dc5b1bbf06ad804e69aec61dc56f3
    Image:         busybox:1.36
    Image ID:      docker.io/library/import-2026-07-14@sha256:9e0210adc53886da123c7186c7cb2ec540965e535d7262a4f00ef8e7a1381a2a
    Port:          <none>
    Host Port:     <none>
    Command:
      sh
      -c
      chmod 1777 /var/lib/cognic-proof-m85c-broker && chgrp 65534 /var/run/docker.sock && chmod 0660 /var/run/docker.sock
    State:          Terminated
      Reason:       Completed
      Exit Code:    0
      Started:      Tue, 14 Jul 2026 05:41:02 +0500
      Finished:     Tue, 14 Jul 2026 05:41:02 +0500
    Ready:          True
    Restart Count:  0
    Environment:
      COGNIC_ALLOW_EXTERNAL_LLM:         true
      COGNIC_POLICY_MODE:                cloud_openai
      COGNIC_ALLOWED_PROVIDERS:          openai
      COGNIC_LITELLM_MASTER_KEY:         vault://secret/cognic/proof-m85c/litellm
      COGNIC_CONVERSATION_CLAIM_TTL_S:   600
      COGNIC_AGENT_RUN_TOKEN_BUDGET:     60000
      COGNIC_AGENT_RUN_WALL_CLOCK_S:     300
      COGNIC_APPROVAL_FOUR_EYES_TTL_S:   1800
      COGNIC_APPROVAL_SINGLE_TTL_S:      1800
      COGNIC_PROOF_M85C_OIDC_ISSUER:     https://cognic-proof-keycloak:8443/realms/proof-m85c
      COGNIC_PROOF_M85C_OIDC_CA_BUNDLE:  /etc/proof-ca/proof-ca.pem
    Mounts:
      /var/lib/cognic-proof-m85c-broker from broker-share (rw)
      /var/run/docker.sock from docker-sock (rw)
Containers:
  agentos:
    Container ID:    containerd://62e90ba7a9ebea48ef08e25e840d5691bb6df10c42229e8e195ee0788814a2d8
    Image:           cognic-agentos:proofm85c
    Image ID:        sha256:29ce91fa33939c19e206b48dab14ad3eb1395c49c0bf16a423aaffff239de2d1
    Port:            8443/TCP
    Host Port:       0/TCP
    SeccompProfile:  RuntimeDefault
    State:           Running
      Started:       Tue, 14 Jul 2026 05:41:03 +0500
    Ready:           True
    Restart Count:   0
    Limits:
      cpu:     2
      memory:  2Gi
    Requests:
      cpu:      250m
      memory:   512Mi
    Liveness:   http-get https://:http/api/v1/healthz delay=0s timeout=5s period=15s #success=1 #failure=3
    Readiness:  http-get https://:http/api/v1/readyz delay=0s timeout=5s period=10s #success=1 #failure=3
    Startup:    http-get https://:http/api/v1/healthz delay=0s timeout=1s period=5s #success=1 #failure=30
    Environment Variables from:
      rel-agentos-config  ConfigMap  Optional: false
    Environment:
      TMPDIR:                            /var/lib/cognic-proof-m85c-broker
      COGNIC_PORT:                       8443
      COGNIC_DATABASE_URL:               <set to the key 'COGNIC_DATABASE_URL' in secret 'rel-agentos-secrets'>  Optional: false
      COGNIC_VAULT_TOKEN:                <set to the key 'COGNIC_VAULT_TOKEN' in secret 'rel-agentos-secrets'>   Optional: false
      COGNIC_ALLOW_EXTERNAL_LLM:         true
      COGNIC_POLICY_MODE:                cloud_openai
      COGNIC_ALLOWED_PROVIDERS:          openai
      COGNIC_LITELLM_MASTER_KEY:         vault://secret/cognic/proof-m85c/litellm
      COGNIC_CONVERSATION_CLAIM_TTL_S:   600
      COGNIC_AGENT_RUN_TOKEN_BUDGET:     60000
      COGNIC_AGENT_RUN_WALL_CLOCK_S:     300
      COGNIC_APPROVAL_FOUR_EYES_TTL_S:   1800
      COGNIC_APPROVAL_SINGLE_TTL_S:      1800
      COGNIC_PROOF_M85C_OIDC_ISSUER:     https://cognic-proof-keycloak:8443/realms/proof-m85c
      COGNIC_PROOF_M85C_OIDC_CA_BUNDLE:  /etc/proof-ca/proof-ca.pem
    Mounts:
      /app/infra/litellm from litellm-config (ro)
      /etc/agentos-tls from agentos-tls (ro)
      /etc/proof-ca from proof-ca (ro)
      /run/cognic/query-context from query-context (ro)
      /tmp from tmp (rw)
      /var/lib/cognic-agentos/object-store from object-store (rw)
      /var/lib/cognic-proof-m85c-broker from broker-share (rw)
      /var/lib/cognic/model-artifacts from model-artifacts (rw)
      /var/run/docker.sock from docker-sock (rw)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True
  Initialized                 True
  Ready                       True
  ContainersReady             True
  PodScheduled                True
Volumes:
  docker-sock:
    Type:          HostPath (bare host directory volume)
    Path:          /var/run/docker.sock
    HostPathType:
  broker-share:
    Type:          HostPath (bare host directory volume)
    Path:          /var/lib/cognic-proof-m85c-broker
    HostPathType:  DirectoryOrCreate
  query-context:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-query-context
    Optional:    false
  agentos-tls:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-agentos-tls
    Optional:    false
  proof-ca:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-ca
    Optional:    false
  litellm-config:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      rel-agentos-litellm
    Optional:  false
  tmp:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  256Mi
  object-store:
    Type:       EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:  5Gi
  model-artifacts:
    Type:        EmptyDir (a temporary directory that shares a pod's lifetime)
    Medium:
    SizeLimit:   5Gi
QoS Class:       Burstable
Node-Selectors:  <none>
Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type     Reason     Age   From               Message
  ----     ------     ----  ----               -------
  Normal   Scheduled  10m   default-scheduler  Successfully assigned cognic-proofm85c/rel-agentos-c796b8c9f-xg47s to cognic-proofm85c-control-plane
  Normal   Pulled     10m   kubelet            Container image "busybox:1.36" already present on machine and can be accessed by the pod
  Normal   Created    10m   kubelet            Container created
  Normal   Started    10m   kubelet            Container started
  Normal   Pulled     10m   kubelet            Container image "cognic-agentos:proofm85c" already present on machine and can be accessed by the pod
  Normal   Created    10m   kubelet            Container created
  Normal   Started    10m   kubelet            Container started
  Warning  Unhealthy  10m   kubelet            Startup probe failed: Get "https://10.244.0.23:8443/api/v1/healthz": dial tcp 10.244.0.23:8443: connect: connection refused
```
- rel-agentos logs (tail 220):
```
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:22,969", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b7835f6ed1e14e74b157e3a97d8109d6", "trace_id": "0091ea35644fd8592018176ef7eea995", "span_id": "af23f6f99fee1ec9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.791, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:32,542", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7981bd7c96ea47aab928f9dc502ee3c1", "trace_id": "4737748f87a8ec200f8c2252c0229852", "span_id": "82565f9cbac670f2", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.252, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:32,955", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4e646d9ab4a14bb88a7a1b66afa29180", "trace_id": "3bdf8e56163b1bb69f49656d759f95e1", "span_id": "c8107146268a895d"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:32,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4e646d9ab4a14bb88a7a1b66afa29180", "trace_id": "3bdf8e56163b1bb69f49656d759f95e1", "span_id": "c8107146268a895d"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:32,977", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4e646d9ab4a14bb88a7a1b66afa29180", "trace_id": "3bdf8e56163b1bb69f49656d759f95e1", "span_id": "c8107146268a895d"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:32,977", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4e646d9ab4a14bb88a7a1b66afa29180", "trace_id": "3bdf8e56163b1bb69f49656d759f95e1", "span_id": "c8107146268a895d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.673, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:42,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-35d26898f74140d191410e15a0171575", "trace_id": "c3ac455a100b33a0e2a860120ed04c4c", "span_id": "3ce1e8da5bc72062"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:42,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-35d26898f74140d191410e15a0171575", "trace_id": "c3ac455a100b33a0e2a860120ed04c4c", "span_id": "3ce1e8da5bc72062"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:42,973", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-35d26898f74140d191410e15a0171575", "trace_id": "c3ac455a100b33a0e2a860120ed04c4c", "span_id": "3ce1e8da5bc72062"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:42,973", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-35d26898f74140d191410e15a0171575", "trace_id": "c3ac455a100b33a0e2a860120ed04c4c", "span_id": "3ce1e8da5bc72062", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.681, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:47,538", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-31b3dfd28a2e416ab09967017932c566", "trace_id": "6b9b955153648d4d1e251b6a5bdce98e", "span_id": "47e837585a2ef284", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.158, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:52,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-90ba8b13ce51499183fa2c2594665a59", "trace_id": "66eac0febe81705851133652a731c360", "span_id": "144e58383dc8de43"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:52,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-90ba8b13ce51499183fa2c2594665a59", "trace_id": "66eac0febe81705851133652a731c360", "span_id": "144e58383dc8de43"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:52,973", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-90ba8b13ce51499183fa2c2594665a59", "trace_id": "66eac0febe81705851133652a731c360", "span_id": "144e58383dc8de43"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:43:52,974", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-90ba8b13ce51499183fa2c2594665a59", "trace_id": "66eac0febe81705851133652a731c360", "span_id": "144e58383dc8de43", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.088, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:02,539", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ec3f0cd90f704749bd28c55a7acd991d", "trace_id": "ff3022bd6d7bb0c8bb8a78e407279f56", "span_id": "bb369bf550ff36fe", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.227, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:02,951", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bce64038bea2420f9f172f22d5c638d5", "trace_id": "191a5535e921b1d4a491d2cdfbba3842", "span_id": "abf92587148bf589"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:02,962", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bce64038bea2420f9f172f22d5c638d5", "trace_id": "191a5535e921b1d4a491d2cdfbba3842", "span_id": "abf92587148bf589"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:02,972", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bce64038bea2420f9f172f22d5c638d5", "trace_id": "191a5535e921b1d4a491d2cdfbba3842", "span_id": "abf92587148bf589"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:02,972", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bce64038bea2420f9f172f22d5c638d5", "trace_id": "191a5535e921b1d4a491d2cdfbba3842", "span_id": "abf92587148bf589", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.621, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:12,954", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fe25d709e0874cba8aa5648ac1469d6e", "trace_id": "dc2023475f79c35cc35f3fb3e4c0ab52", "span_id": "7ac7020ff05af18b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:12,967", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fe25d709e0874cba8aa5648ac1469d6e", "trace_id": "dc2023475f79c35cc35f3fb3e4c0ab52", "span_id": "7ac7020ff05af18b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:12,978", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fe25d709e0874cba8aa5648ac1469d6e", "trace_id": "dc2023475f79c35cc35f3fb3e4c0ab52", "span_id": "7ac7020ff05af18b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:12,978", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fe25d709e0874cba8aa5648ac1469d6e", "trace_id": "dc2023475f79c35cc35f3fb3e4c0ab52", "span_id": "7ac7020ff05af18b", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 29.042, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:17,536", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4895a66fb6b448d5a6065dace322e53d", "trace_id": "c0791230022259be42d59670b320499d", "span_id": "9f445bf96196cb57", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.151, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:22,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1853ef52f7064a78965aacda22128dd8", "trace_id": "355968ea17168d35a9a18c6454f5db8b", "span_id": "243207687096f18e"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:22,955", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1853ef52f7064a78965aacda22128dd8", "trace_id": "355968ea17168d35a9a18c6454f5db8b", "span_id": "243207687096f18e"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:22,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1853ef52f7064a78965aacda22128dd8", "trace_id": "355968ea17168d35a9a18c6454f5db8b", "span_id": "243207687096f18e"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:22,966", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1853ef52f7064a78965aacda22128dd8", "trace_id": "355968ea17168d35a9a18c6454f5db8b", "span_id": "243207687096f18e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.211, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:32,541", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0f8754cf0f3e491999f2a9344d19c121", "trace_id": "aa4ddb9990b03e4795ff093ca937b3c4", "span_id": "ab23ff65702603ae", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.404, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:32,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cef7ff67f02542369c1f4a77694ebe72", "trace_id": "53c8dc5477e1d6abc6d3859606ff9de4", "span_id": "26b292e209511624"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:32,964", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cef7ff67f02542369c1f4a77694ebe72", "trace_id": "53c8dc5477e1d6abc6d3859606ff9de4", "span_id": "26b292e209511624"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:32,977", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cef7ff67f02542369c1f4a77694ebe72", "trace_id": "53c8dc5477e1d6abc6d3859606ff9de4", "span_id": "26b292e209511624"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:32,977", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-cef7ff67f02542369c1f4a77694ebe72", "trace_id": "53c8dc5477e1d6abc6d3859606ff9de4", "span_id": "26b292e209511624", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 32.255, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:42,943", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-daee06d5a8eb4f779d62b6cb24343e13", "trace_id": "4e4503c7ed558989e1dfd5e3f6a72114", "span_id": "05c84bf86444e19b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:42,953", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-daee06d5a8eb4f779d62b6cb24343e13", "trace_id": "4e4503c7ed558989e1dfd5e3f6a72114", "span_id": "05c84bf86444e19b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:42,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-daee06d5a8eb4f779d62b6cb24343e13", "trace_id": "4e4503c7ed558989e1dfd5e3f6a72114", "span_id": "05c84bf86444e19b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:42,963", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-daee06d5a8eb4f779d62b6cb24343e13", "trace_id": "4e4503c7ed558989e1dfd5e3f6a72114", "span_id": "05c84bf86444e19b", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.208, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:47,534", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8dfdfbd9c83b49ca8119e8698b766d0c", "trace_id": "27d7fffaa72e57e11f8d9b1a38452788", "span_id": "2264043dd419c1c5", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.162, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:52,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e9f19a7fb6984130a3c15e1fedfb48a0", "trace_id": "96909889133a29e73a53a45ef09676c6", "span_id": "4c0ad12eebce22c4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:52,957", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e9f19a7fb6984130a3c15e1fedfb48a0", "trace_id": "96909889133a29e73a53a45ef09676c6", "span_id": "4c0ad12eebce22c4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:52,967", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e9f19a7fb6984130a3c15e1fedfb48a0", "trace_id": "96909889133a29e73a53a45ef09676c6", "span_id": "4c0ad12eebce22c4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:44:52,968", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e9f19a7fb6984130a3c15e1fedfb48a0", "trace_id": "96909889133a29e73a53a45ef09676c6", "span_id": "4c0ad12eebce22c4", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.634, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:02,538", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c756ebc7bd2f485ebcec4bfc286d7da0", "trace_id": "e7fe795ce89851801066c18cc51bb86f", "span_id": "e6f83482550ae3e3", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.409, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:02,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5a93df710c49466cbd6604396f8eeef8", "trace_id": "842e4a034a29ca76dcb8e0764195f11f", "span_id": "9056d3fbdb2c3c2b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:02,965", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5a93df710c49466cbd6604396f8eeef8", "trace_id": "842e4a034a29ca76dcb8e0764195f11f", "span_id": "9056d3fbdb2c3c2b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:02,977", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5a93df710c49466cbd6604396f8eeef8", "trace_id": "842e4a034a29ca76dcb8e0764195f11f", "span_id": "9056d3fbdb2c3c2b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:02,977", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5a93df710c49466cbd6604396f8eeef8", "trace_id": "842e4a034a29ca76dcb8e0764195f11f", "span_id": "9056d3fbdb2c3c2b", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 33.177, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:12,942", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2e9eb9018c504380af1472229f8b6dad", "trace_id": "42382e5926b743d408f9116edd379068", "span_id": "44002825e42964d4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:12,953", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2e9eb9018c504380af1472229f8b6dad", "trace_id": "42382e5926b743d408f9116edd379068", "span_id": "44002825e42964d4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:12,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2e9eb9018c504380af1472229f8b6dad", "trace_id": "42382e5926b743d408f9116edd379068", "span_id": "44002825e42964d4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:12,964", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2e9eb9018c504380af1472229f8b6dad", "trace_id": "42382e5926b743d408f9116edd379068", "span_id": "44002825e42964d4", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.073, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:17,535", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f3c64c23bc2846c491ecf30b3f0d20e4", "trace_id": "08fea1a44e6a9a40acb7e48fe30f3199", "span_id": "47083209764e4c9b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.237, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:22,944", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d97b28c8454b4ae395b9f4df3e8d5bd5", "trace_id": "994a4e3be8848ccd96746bd920d3c1b9", "span_id": "9694ad33389792ef"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:22,957", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d97b28c8454b4ae395b9f4df3e8d5bd5", "trace_id": "994a4e3be8848ccd96746bd920d3c1b9", "span_id": "9694ad33389792ef"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:22,968", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d97b28c8454b4ae395b9f4df3e8d5bd5", "trace_id": "994a4e3be8848ccd96746bd920d3c1b9", "span_id": "9694ad33389792ef"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:22,969", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d97b28c8454b4ae395b9f4df3e8d5bd5", "trace_id": "994a4e3be8848ccd96746bd920d3c1b9", "span_id": "9694ad33389792ef", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 29.378, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:32,535", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a9882c5d169c4329b9ad95fa255f5e93", "trace_id": "a30070f748c03233ac8dd455dc3477c3", "span_id": "e40483ad56bb2aab", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.206, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:32,944", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-882738e894c74cd2bc0c51f146305206", "trace_id": "1761fb27274784eafdc49038f7d1bf14", "span_id": "72e8067bc21a2d55"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:32,956", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-882738e894c74cd2bc0c51f146305206", "trace_id": "1761fb27274784eafdc49038f7d1bf14", "span_id": "72e8067bc21a2d55"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:32,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-882738e894c74cd2bc0c51f146305206", "trace_id": "1761fb27274784eafdc49038f7d1bf14", "span_id": "72e8067bc21a2d55"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:32,967", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-882738e894c74cd2bc0c51f146305206", "trace_id": "1761fb27274784eafdc49038f7d1bf14", "span_id": "72e8067bc21a2d55", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.488, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:42,946", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9147ab8f52ca4cac86dac5b954dd1af0", "trace_id": "84c5391ae1a99fc1b467ee483ef23916", "span_id": "e452b002b2baaf8a"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:42,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9147ab8f52ca4cac86dac5b954dd1af0", "trace_id": "84c5391ae1a99fc1b467ee483ef23916", "span_id": "e452b002b2baaf8a"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:42,967", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9147ab8f52ca4cac86dac5b954dd1af0", "trace_id": "84c5391ae1a99fc1b467ee483ef23916", "span_id": "e452b002b2baaf8a"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:42,968", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9147ab8f52ca4cac86dac5b954dd1af0", "trace_id": "84c5391ae1a99fc1b467ee483ef23916", "span_id": "e452b002b2baaf8a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.247, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:47,536", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ab142bc36cac416a94bee020ae1fc901", "trace_id": "ed08981eda1b5e4c525e5112d8d12952", "span_id": "e19383ae1d1daaec", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.278, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:52,946", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7e1420995e784c8d98cca7e1aaed3470", "trace_id": "02a8a816bff72b2c7fb4ad6b0e7e7cd4", "span_id": "7f59f199d99f27a7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:52,957", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7e1420995e784c8d98cca7e1aaed3470", "trace_id": "02a8a816bff72b2c7fb4ad6b0e7e7cd4", "span_id": "7f59f199d99f27a7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:52,967", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7e1420995e784c8d98cca7e1aaed3470", "trace_id": "02a8a816bff72b2c7fb4ad6b0e7e7cd4", "span_id": "7f59f199d99f27a7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:45:52,968", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7e1420995e784c8d98cca7e1aaed3470", "trace_id": "02a8a816bff72b2c7fb4ad6b0e7e7cd4", "span_id": "7f59f199d99f27a7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.774, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:02,535", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-07212bd50f7f45daa497d085dd35f11c", "trace_id": "3fbee29ecd8284d1fc8f4cbc94e348de", "span_id": "d68abb8e67eed384", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.298, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:02,948", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0b20cc132c8843b89d47ab1e5b54c5a1", "trace_id": "d743207dd7180909896a14438fc7c495", "span_id": "81717806c2a39c5c"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:02,960", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0b20cc132c8843b89d47ab1e5b54c5a1", "trace_id": "d743207dd7180909896a14438fc7c495", "span_id": "81717806c2a39c5c"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:02,972", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0b20cc132c8843b89d47ab1e5b54c5a1", "trace_id": "d743207dd7180909896a14438fc7c495", "span_id": "81717806c2a39c5c"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:02,973", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0b20cc132c8843b89d47ab1e5b54c5a1", "trace_id": "d743207dd7180909896a14438fc7c495", "span_id": "81717806c2a39c5c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 31.666, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:12,948", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99316d229ed8436ba3344d4615ad6379", "trace_id": "05aa5ffbb87bbc294f91228a19164434", "span_id": "9ee60e6c2534c420"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:12,959", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99316d229ed8436ba3344d4615ad6379", "trace_id": "05aa5ffbb87bbc294f91228a19164434", "span_id": "9ee60e6c2534c420"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:12,969", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99316d229ed8436ba3344d4615ad6379", "trace_id": "05aa5ffbb87bbc294f91228a19164434", "span_id": "9ee60e6c2534c420"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:12,970", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-99316d229ed8436ba3344d4615ad6379", "trace_id": "05aa5ffbb87bbc294f91228a19164434", "span_id": "9ee60e6c2534c420", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.641, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:17,533", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f52ae6fb5f624634a301e31c28b11ddd", "trace_id": "c03a10650dac944fd4ef0a05082eed77", "span_id": "61cd48d561cf10f4", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.341, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:22,938", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c7079dc3f1344326a076962ed3039c79", "trace_id": "c3e28fe164212998614015dc0d0d7d66", "span_id": "224acdad90956653"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:22,950", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c7079dc3f1344326a076962ed3039c79", "trace_id": "c3e28fe164212998614015dc0d0d7d66", "span_id": "224acdad90956653"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:22,961", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c7079dc3f1344326a076962ed3039c79", "trace_id": "c3e28fe164212998614015dc0d0d7d66", "span_id": "224acdad90956653"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:22,962", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c7079dc3f1344326a076962ed3039c79", "trace_id": "c3e28fe164212998614015dc0d0d7d66", "span_id": "224acdad90956653", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.783, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:32,529", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8ad57f8e127e4f5cab15116453bdfc8b", "trace_id": "120185d83340bd6823dab99bd9b52cdb", "span_id": "de509ca69285bb5b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.244, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:32,940", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b877406ce97247e4bb66a2dbd58b25e3", "trace_id": "4cf3b05ad3d590b2c49f52ff013f19ba", "span_id": "1fd3624ecaf84fbd"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:32,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b877406ce97247e4bb66a2dbd58b25e3", "trace_id": "4cf3b05ad3d590b2c49f52ff013f19ba", "span_id": "1fd3624ecaf84fbd"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:32,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b877406ce97247e4bb66a2dbd58b25e3", "trace_id": "4cf3b05ad3d590b2c49f52ff013f19ba", "span_id": "1fd3624ecaf84fbd"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:32,963", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b877406ce97247e4bb66a2dbd58b25e3", "trace_id": "4cf3b05ad3d590b2c49f52ff013f19ba", "span_id": "1fd3624ecaf84fbd", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.137, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:42,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-388df5d4be33479e957ad9bc56a2580e", "trace_id": "b82cf8b32301e34d95fc2fde09f9b596", "span_id": "243203dc52a4266a"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:42,956", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-388df5d4be33479e957ad9bc56a2580e", "trace_id": "b82cf8b32301e34d95fc2fde09f9b596", "span_id": "243203dc52a4266a"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:42,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-388df5d4be33479e957ad9bc56a2580e", "trace_id": "b82cf8b32301e34d95fc2fde09f9b596", "span_id": "243203dc52a4266a"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:42,967", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-388df5d4be33479e957ad9bc56a2580e", "trace_id": "b82cf8b32301e34d95fc2fde09f9b596", "span_id": "243203dc52a4266a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.837, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:47,532", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-799978142bc54a3483406f0a7bfa0c18", "trace_id": "cd13170e69de026dbafb46eac4183c67", "span_id": "6b72fbfffdf4bf10", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.212, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:52,940", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4c773269b44a40b3b23e7faf8337ac0a", "trace_id": "baa0e05fc30a798d114713febf27dbe3", "span_id": "eb7d211d1e6a82e5"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:52,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4c773269b44a40b3b23e7faf8337ac0a", "trace_id": "baa0e05fc30a798d114713febf27dbe3", "span_id": "eb7d211d1e6a82e5"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:52,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4c773269b44a40b3b23e7faf8337ac0a", "trace_id": "baa0e05fc30a798d114713febf27dbe3", "span_id": "eb7d211d1e6a82e5"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:46:52,963", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4c773269b44a40b3b23e7faf8337ac0a", "trace_id": "baa0e05fc30a798d114713febf27dbe3", "span_id": "eb7d211d1e6a82e5", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.676, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:02,529", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-896e0d04f38943f7802d9ab01232737e", "trace_id": "bd78af8a5e6dd91f9877c8d9271cf055", "span_id": "12e22159194cc385", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.212, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:02,941", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b410ae7f1a85408bb135ea7f519b6b5d", "trace_id": "3e5bc00c2c802cf613d1f153b7ebabb3", "span_id": "c699abc487155fc4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:02,954", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b410ae7f1a85408bb135ea7f519b6b5d", "trace_id": "3e5bc00c2c802cf613d1f153b7ebabb3", "span_id": "c699abc487155fc4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:02,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b410ae7f1a85408bb135ea7f519b6b5d", "trace_id": "3e5bc00c2c802cf613d1f153b7ebabb3", "span_id": "c699abc487155fc4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:02,967", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b410ae7f1a85408bb135ea7f519b6b5d", "trace_id": "3e5bc00c2c802cf613d1f153b7ebabb3", "span_id": "c699abc487155fc4", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 32.346, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:12,943", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a3a7226b5df146a29445129161417af1", "trace_id": "8fc9d4c7a04290c5c939ea784aca6290", "span_id": "079f947eb74140cc"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:12,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a3a7226b5df146a29445129161417af1", "trace_id": "8fc9d4c7a04290c5c939ea784aca6290", "span_id": "079f947eb74140cc"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:12,971", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a3a7226b5df146a29445129161417af1", "trace_id": "8fc9d4c7a04290c5c939ea784aca6290", "span_id": "079f947eb74140cc"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:12,971", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a3a7226b5df146a29445129161417af1", "trace_id": "8fc9d4c7a04290c5c939ea784aca6290", "span_id": "079f947eb74140cc", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 36.072, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:17,530", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f3af73640c1b46baa78ac5ebcf61dbf2", "trace_id": "956614be76f1a9dda2b1dddb36a4f9a9", "span_id": "a02c8eb06dbe8f0a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.302, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:22,934", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1bd8c8dbfdfa4007b8a8d12591467ed4", "trace_id": "b2c102df0638aecd24ece76662d72eda", "span_id": "8e9967d5c3416114"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:22,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1bd8c8dbfdfa4007b8a8d12591467ed4", "trace_id": "b2c102df0638aecd24ece76662d72eda", "span_id": "8e9967d5c3416114"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:22,955", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1bd8c8dbfdfa4007b8a8d12591467ed4", "trace_id": "b2c102df0638aecd24ece76662d72eda", "span_id": "8e9967d5c3416114"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:22,955", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1bd8c8dbfdfa4007b8a8d12591467ed4", "trace_id": "b2c102df0638aecd24ece76662d72eda", "span_id": "8e9967d5c3416114", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.818, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:32,526", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4eb5f85228a243bd9daa83917103e811", "trace_id": "32428d255356510a2a189e9cda74ce88", "span_id": "a1650ab4e7a55453", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.199, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:32,936", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5b917736f5b544f4b6217fdb31344d2d", "trace_id": "1017215f0e5b20822c597b0365fd729a", "span_id": "41ab9788234386b1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:32,947", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5b917736f5b544f4b6217fdb31344d2d", "trace_id": "1017215f0e5b20822c597b0365fd729a", "span_id": "41ab9788234386b1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:32,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5b917736f5b544f4b6217fdb31344d2d", "trace_id": "1017215f0e5b20822c597b0365fd729a", "span_id": "41ab9788234386b1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:32,958", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5b917736f5b544f4b6217fdb31344d2d", "trace_id": "1017215f0e5b20822c597b0365fd729a", "span_id": "41ab9788234386b1", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.314, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:42,942", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-80b407d39572426d9d7dccfced6a8894", "trace_id": "ee5b299256b1356ccfe75d39a650a23b", "span_id": "cf7e070fcc6564ba"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:42,954", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-80b407d39572426d9d7dccfced6a8894", "trace_id": "ee5b299256b1356ccfe75d39a650a23b", "span_id": "cf7e070fcc6564ba"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:42,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-80b407d39572426d9d7dccfced6a8894", "trace_id": "ee5b299256b1356ccfe75d39a650a23b", "span_id": "cf7e070fcc6564ba"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:42,966", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-80b407d39572426d9d7dccfced6a8894", "trace_id": "ee5b299256b1356ccfe75d39a650a23b", "span_id": "cf7e070fcc6564ba", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 30.611, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:47,528", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a779e3566a7948c8a733da575e06592e", "trace_id": "cbc97fc5707fcca0e7e6502365995b22", "span_id": "941483a1e6a427eb", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.252, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:52,936", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-89540fe2e0fa49a89a882a2f09d32272", "trace_id": "26698e2de38ebc293946adac35a430f0", "span_id": "4f3190c31c87ccd7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:52,948", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-89540fe2e0fa49a89a882a2f09d32272", "trace_id": "26698e2de38ebc293946adac35a430f0", "span_id": "4f3190c31c87ccd7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:52,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-89540fe2e0fa49a89a882a2f09d32272", "trace_id": "26698e2de38ebc293946adac35a430f0", "span_id": "4f3190c31c87ccd7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:47:52,958", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-89540fe2e0fa49a89a882a2f09d32272", "trace_id": "26698e2de38ebc293946adac35a430f0", "span_id": "4f3190c31c87ccd7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.441, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:02,523", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8fef90ea262a400aabce46c0d66f9b57", "trace_id": "f3a536871ba5f03195e662f95c0e4855", "span_id": "3bed49e1677b8b65", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.426, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:02,936", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f6dca74a7f6b42f5a7b574575ef9750b", "trace_id": "db54b5a1c8f82b1608306b45f899be1a", "span_id": "3a529e2cb9b8b633"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:02,947", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f6dca74a7f6b42f5a7b574575ef9750b", "trace_id": "db54b5a1c8f82b1608306b45f899be1a", "span_id": "3a529e2cb9b8b633"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:02,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f6dca74a7f6b42f5a7b574575ef9750b", "trace_id": "db54b5a1c8f82b1608306b45f899be1a", "span_id": "3a529e2cb9b8b633"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:02,958", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f6dca74a7f6b42f5a7b574575ef9750b", "trace_id": "db54b5a1c8f82b1608306b45f899be1a", "span_id": "3a529e2cb9b8b633", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.316, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:12,936", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b7712dd6f5e74c1aafc31367c19bfce8", "trace_id": "499765b50056078e5aa8d6cfd0793c6d", "span_id": "dcb2eb98c9b4e381"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:12,947", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b7712dd6f5e74c1aafc31367c19bfce8", "trace_id": "499765b50056078e5aa8d6cfd0793c6d", "span_id": "dcb2eb98c9b4e381"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:12,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b7712dd6f5e74c1aafc31367c19bfce8", "trace_id": "499765b50056078e5aa8d6cfd0793c6d", "span_id": "dcb2eb98c9b4e381"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:12,959", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b7712dd6f5e74c1aafc31367c19bfce8", "trace_id": "499765b50056078e5aa8d6cfd0793c6d", "span_id": "dcb2eb98c9b4e381", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.278, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:17,523", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-21a79fa397174a8fb9d263eae88cc9eb", "trace_id": "41aa9461e9f2fc9af0ef5f500d653614", "span_id": "de53df2618fd5a88", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.212, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:22,931", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4b039c0e67cb424fa8ac98a5be200f5a", "trace_id": "e5e26748b82dcb3e3376d388d925025e", "span_id": "430267232c96931d"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:22,942", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4b039c0e67cb424fa8ac98a5be200f5a", "trace_id": "e5e26748b82dcb3e3376d388d925025e", "span_id": "430267232c96931d"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:22,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4b039c0e67cb424fa8ac98a5be200f5a", "trace_id": "e5e26748b82dcb3e3376d388d925025e", "span_id": "430267232c96931d"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:22,952", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4b039c0e67cb424fa8ac98a5be200f5a", "trace_id": "e5e26748b82dcb3e3376d388d925025e", "span_id": "430267232c96931d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.336, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:32,522", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e74f70b3193d46a599e97daee618687a", "trace_id": "464b46697850560bd5f19b88369f3fc8", "span_id": "f96c1edabc10b1ce", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.19, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:32,936", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fb78ec0702c344fd9e0cc4967ce75f9a", "trace_id": "65957bbfe34a3f2241499eb3d16dbc07", "span_id": "f56295d8800da80b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:32,949", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fb78ec0702c344fd9e0cc4967ce75f9a", "trace_id": "65957bbfe34a3f2241499eb3d16dbc07", "span_id": "f56295d8800da80b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:32,961", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fb78ec0702c344fd9e0cc4967ce75f9a", "trace_id": "65957bbfe34a3f2241499eb3d16dbc07", "span_id": "f56295d8800da80b"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:32,962", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fb78ec0702c344fd9e0cc4967ce75f9a", "trace_id": "65957bbfe34a3f2241499eb3d16dbc07", "span_id": "f56295d8800da80b", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 31.995, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:42,937", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-df7e94a650fb4cc0ab8b15505ff94fe2", "trace_id": "d4c27ff51b58c0bd04400f6f0619354a", "span_id": "a60ce8227f44747f"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:42,948", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-df7e94a650fb4cc0ab8b15505ff94fe2", "trace_id": "d4c27ff51b58c0bd04400f6f0619354a", "span_id": "a60ce8227f44747f"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:42,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-df7e94a650fb4cc0ab8b15505ff94fe2", "trace_id": "d4c27ff51b58c0bd04400f6f0619354a", "span_id": "a60ce8227f44747f"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:42,959", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-df7e94a650fb4cc0ab8b15505ff94fe2", "trace_id": "d4c27ff51b58c0bd04400f6f0619354a", "span_id": "a60ce8227f44747f", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.837, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:47,524", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-59cbeee1b8b042d8bd526def43ca80ad", "trace_id": "d6e2ed785c58c4b8b206339bb30942bb", "span_id": "15dddc72f725572a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.248, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:52,933", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2292b4116d7944a28034cf5044c6bbed", "trace_id": "03d48fe3f59acb2a9607cd1d6d05f5d9", "span_id": "d46b502afada9026"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:52,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2292b4116d7944a28034cf5044c6bbed", "trace_id": "03d48fe3f59acb2a9607cd1d6d05f5d9", "span_id": "d46b502afada9026"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:52,955", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2292b4116d7944a28034cf5044c6bbed", "trace_id": "03d48fe3f59acb2a9607cd1d6d05f5d9", "span_id": "d46b502afada9026"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:48:52,955", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2292b4116d7944a28034cf5044c6bbed", "trace_id": "03d48fe3f59acb2a9607cd1d6d05f5d9", "span_id": "d46b502afada9026", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.52, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:02,521", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3c1cfbcfe99c4377b5c1522efc72353e", "trace_id": "0a74fa1286ceb17b9fbafcbbba3e98d0", "span_id": "0b94ae03e9159bf6", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.202, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:02,934", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4508e13fcae044d69f0b46a779f3d710", "trace_id": "89894ba65107ded691244f60eb7d7662", "span_id": "3f694acb94ed23be"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:02,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4508e13fcae044d69f0b46a779f3d710", "trace_id": "89894ba65107ded691244f60eb7d7662", "span_id": "3f694acb94ed23be"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:02,956", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4508e13fcae044d69f0b46a779f3d710", "trace_id": "89894ba65107ded691244f60eb7d7662", "span_id": "3f694acb94ed23be"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:02,957", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4508e13fcae044d69f0b46a779f3d710", "trace_id": "89894ba65107ded691244f60eb7d7662", "span_id": "3f694acb94ed23be", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.162, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:12,932", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7ad0149006454d42a87ee2736fe1b949", "trace_id": "7cf6df31c1e073679704f4a2efa5e41d", "span_id": "fb43e9b9531ba4e1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:12,944", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7ad0149006454d42a87ee2736fe1b949", "trace_id": "7cf6df31c1e073679704f4a2efa5e41d", "span_id": "fb43e9b9531ba4e1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:12,955", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7ad0149006454d42a87ee2736fe1b949", "trace_id": "7cf6df31c1e073679704f4a2efa5e41d", "span_id": "fb43e9b9531ba4e1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:12,956", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7ad0149006454d42a87ee2736fe1b949", "trace_id": "7cf6df31c1e073679704f4a2efa5e41d", "span_id": "fb43e9b9531ba4e1", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.24, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:17,521", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0d781b2ce5fd447b82cb41fddd3076ca", "trace_id": "42d4b1e4bc1f815880bf2fa2ec29a5aa", "span_id": "1b3b170b1be46c3f", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.19, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:22,928", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ea36e1121ee0416fbae3b14d7928ef06", "trace_id": "6b1754f1e994557e2caa843477345765", "span_id": "3c8db0e865664d22"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:22,941", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ea36e1121ee0416fbae3b14d7928ef06", "trace_id": "6b1754f1e994557e2caa843477345765", "span_id": "3c8db0e865664d22"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:22,951", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ea36e1121ee0416fbae3b14d7928ef06", "trace_id": "6b1754f1e994557e2caa843477345765", "span_id": "3c8db0e865664d22"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:22,952", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ea36e1121ee0416fbae3b14d7928ef06", "trace_id": "6b1754f1e994557e2caa843477345765", "span_id": "3c8db0e865664d22", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.923, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:32,524", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-74a990946fb3445996259d5803d13c62", "trace_id": "a074836513f56c79020297c67aa569d7", "span_id": "4aa5683f071bb030", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.201, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:32,934", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-799f3fc78404416fb28947dd6963d0d7", "trace_id": "6563a5a78fd2ee2e05a459d1d21e8841", "span_id": "c50af397ec73c4b7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:32,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-799f3fc78404416fb28947dd6963d0d7", "trace_id": "6563a5a78fd2ee2e05a459d1d21e8841", "span_id": "c50af397ec73c4b7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:32,956", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-799f3fc78404416fb28947dd6963d0d7", "trace_id": "6563a5a78fd2ee2e05a459d1d21e8841", "span_id": "c50af397ec73c4b7"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:32,956", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-799f3fc78404416fb28947dd6963d0d7", "trace_id": "6563a5a78fd2ee2e05a459d1d21e8841", "span_id": "c50af397ec73c4b7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.84, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:42,926", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c20117c5d9264d01b489da436d202824", "trace_id": "90cba92ac800127b7475f85741540a27", "span_id": "918e7d80a4142c37"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:42,936", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c20117c5d9264d01b489da436d202824", "trace_id": "90cba92ac800127b7475f85741540a27", "span_id": "918e7d80a4142c37"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:42,946", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c20117c5d9264d01b489da436d202824", "trace_id": "90cba92ac800127b7475f85741540a27", "span_id": "918e7d80a4142c37"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:42,946", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c20117c5d9264d01b489da436d202824", "trace_id": "90cba92ac800127b7475f85741540a27", "span_id": "918e7d80a4142c37", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.57, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:47,520", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-58908094700040a19f382e6908605f88", "trace_id": "38bc86a8a05137398d8fe3893c58ab33", "span_id": "d75998710c144964", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.203, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:52,931", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-86d52a176f8f4460be54fcf626518312", "trace_id": "b0843716375d4f5bad1231f2a71928c5", "span_id": "ef69fa01d5fca2e9"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:52,941", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-86d52a176f8f4460be54fcf626518312", "trace_id": "b0843716375d4f5bad1231f2a71928c5", "span_id": "ef69fa01d5fca2e9"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:52,951", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-86d52a176f8f4460be54fcf626518312", "trace_id": "b0843716375d4f5bad1231f2a71928c5", "span_id": "ef69fa01d5fca2e9"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:49:52,952", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-86d52a176f8f4460be54fcf626518312", "trace_id": "b0843716375d4f5bad1231f2a71928c5", "span_id": "ef69fa01d5fca2e9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.243, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:02,518", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e9837aa709a24c1eb55277950746b508", "trace_id": "17e47705865e7824ba22d57ce06f5627", "span_id": "ef8194e657cc7f50", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.314, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:02,932", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5d62ccd3543c4e5cbcd20d1db86fbfd4", "trace_id": "961300faeee47bbfe1594119b9ccdeba", "span_id": "e8363020eb0e8e61"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:02,945", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5d62ccd3543c4e5cbcd20d1db86fbfd4", "trace_id": "961300faeee47bbfe1594119b9ccdeba", "span_id": "e8363020eb0e8e61"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:02,957", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5d62ccd3543c4e5cbcd20d1db86fbfd4", "trace_id": "961300faeee47bbfe1594119b9ccdeba", "span_id": "e8363020eb0e8e61"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:02,958", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5d62ccd3543c4e5cbcd20d1db86fbfd4", "trace_id": "961300faeee47bbfe1594119b9ccdeba", "span_id": "e8363020eb0e8e61", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 32.881, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:12,929", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ef7d2a2cf4c646528f5406f9cc4a9305", "trace_id": "7ce0309fd9324f9f74dd8782b5debcdf", "span_id": "68c0ea5d1f20a4e4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:12,941", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ef7d2a2cf4c646528f5406f9cc4a9305", "trace_id": "7ce0309fd9324f9f74dd8782b5debcdf", "span_id": "68c0ea5d1f20a4e4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:12,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ef7d2a2cf4c646528f5406f9cc4a9305", "trace_id": "7ce0309fd9324f9f74dd8782b5debcdf", "span_id": "68c0ea5d1f20a4e4"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:12,952", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ef7d2a2cf4c646528f5406f9cc4a9305", "trace_id": "7ce0309fd9324f9f74dd8782b5debcdf", "span_id": "68c0ea5d1f20a4e4", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.754, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:17,518", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2fb959ed073f4205aa532e47466a6b54", "trace_id": "dd329204a6f0d741d13e0004a61ec97e", "span_id": "4905de1fbbe85b6e", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.219, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:22,925", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-45d8ba112f3c43159b9f7b30dd7997c0", "trace_id": "e06b7dbf4ea79bb03285ddc2551eb352", "span_id": "7e3975c4367758ce"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:22,938", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-45d8ba112f3c43159b9f7b30dd7997c0", "trace_id": "e06b7dbf4ea79bb03285ddc2551eb352", "span_id": "7e3975c4367758ce"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:22,950", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-45d8ba112f3c43159b9f7b30dd7997c0", "trace_id": "e06b7dbf4ea79bb03285ddc2551eb352", "span_id": "7e3975c4367758ce"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:22,951", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-45d8ba112f3c43159b9f7b30dd7997c0", "trace_id": "e06b7dbf4ea79bb03285ddc2551eb352", "span_id": "7e3975c4367758ce", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 29.458, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:32,519", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d9c38e139205492496210f46ff502b22", "trace_id": "61252d8c73b9be701636e75931d00dc4", "span_id": "cf7eef642186e1c4", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.465, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:32,931", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-022124c41bb7477e945b9155b8c56062", "trace_id": "7cd58a7ee27aab6685945031c7690987", "span_id": "894bde6cbf118fae"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:32,942", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-022124c41bb7477e945b9155b8c56062", "trace_id": "7cd58a7ee27aab6685945031c7690987", "span_id": "894bde6cbf118fae"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:32,952", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-022124c41bb7477e945b9155b8c56062", "trace_id": "7cd58a7ee27aab6685945031c7690987", "span_id": "894bde6cbf118fae"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:32,953", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-022124c41bb7477e945b9155b8c56062", "trace_id": "7cd58a7ee27aab6685945031c7690987", "span_id": "894bde6cbf118fae", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.562, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:42,934", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-603bf1b5d22842f38115aeb5fbd21417", "trace_id": "f1eba85bd42dec106060fb772ea863c2", "span_id": "476899f7becc82e0"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:42,947", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-603bf1b5d22842f38115aeb5fbd21417", "trace_id": "f1eba85bd42dec106060fb772ea863c2", "span_id": "476899f7becc82e0"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:42,958", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-603bf1b5d22842f38115aeb5fbd21417", "trace_id": "f1eba85bd42dec106060fb772ea863c2", "span_id": "476899f7becc82e0"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:42,958", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-603bf1b5d22842f38115aeb5fbd21417", "trace_id": "f1eba85bd42dec106060fb772ea863c2", "span_id": "476899f7becc82e0", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.944, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:47,516", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b23f9841497448038f33271820601b10", "trace_id": "9ea606599a334b25ad58a20ee34022e1", "span_id": "695151ee6035601d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.228, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:52,926", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-64b20ecb1e66433a83244394a52b196b", "trace_id": "54e9bc1ba3d3a1e74b5219096e2d5536", "span_id": "cb927d990e52ae79"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:52,937", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-64b20ecb1e66433a83244394a52b196b", "trace_id": "54e9bc1ba3d3a1e74b5219096e2d5536", "span_id": "cb927d990e52ae79"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:52,947", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-64b20ecb1e66433a83244394a52b196b", "trace_id": "54e9bc1ba3d3a1e74b5219096e2d5536", "span_id": "cb927d990e52ae79"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:50:52,947", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-64b20ecb1e66433a83244394a52b196b", "trace_id": "54e9bc1ba3d3a1e74b5219096e2d5536", "span_id": "cb927d990e52ae79", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.263, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:02,513", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7c252ecf9084479a992a85360f4a10e9", "trace_id": "99be6bb65a287be03ae840c8752dc0a9", "span_id": "68197ec0f972d628", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.204, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:02,919", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d8b4d2a419ff43a1adaf59fd68dd38bd", "trace_id": "3cfb92b067b5a0bfaf202bb649186eaf", "span_id": "f0298c5ff813fac3"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:02,930", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d8b4d2a419ff43a1adaf59fd68dd38bd", "trace_id": "3cfb92b067b5a0bfaf202bb649186eaf", "span_id": "f0298c5ff813fac3"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:02,940", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d8b4d2a419ff43a1adaf59fd68dd38bd", "trace_id": "3cfb92b067b5a0bfaf202bb649186eaf", "span_id": "f0298c5ff813fac3"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:02,941", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d8b4d2a419ff43a1adaf59fd68dd38bd", "trace_id": "3cfb92b067b5a0bfaf202bb649186eaf", "span_id": "f0298c5ff813fac3", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.016, "client_addr": "10.244.0.1"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:12,927", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c10a2d8e13da40868bc7caf949130fde", "trace_id": "5963f128eba59140e05a81d1d00dc781", "span_id": "031e9609ca4ab808"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:12,939", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c10a2d8e13da40868bc7caf949130fde", "trace_id": "5963f128eba59140e05a81d1d00dc781", "span_id": "031e9609ca4ab808"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:12,950", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c10a2d8e13da40868bc7caf949130fde", "trace_id": "5963f128eba59140e05a81d1d00dc781", "span_id": "031e9609ca4ab808"}
[pod/rel-agentos-c796b8c9f-xg47s/agentos] {"ts": "2026-07-14 00:51:12,950", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c10a2d8e13da40868bc7caf949130fde", "trace_id": "5963f128eba59140e05a81d1d00dc781", "span_id": "031e9609ca4ab808", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.769, "client_addr": "10.244.0.1"}
```
- namespace events (tail 160):
```
12m         Normal    ScalingReplicaSet   deployment/redis                             Scaled up replica set redis-74c49dd754 from 0 to 1
12m         Normal    SuccessfulCreate    replicaset/redis-74c49dd754                  Created pod: redis-74c49dd754-65sn7
12m         Normal    Scheduled           pod/redis-74c49dd754-65sn7                   Successfully assigned cognic-proofm85c/redis-74c49dd754-65sn7 to cognic-proofm85c-control-plane
12m         Normal    ScalingReplicaSet   deployment/qdrant                            Scaled up replica set qdrant-54644949b7 from 0 to 1
12m         Normal    SuccessfulCreate    replicaset/qdrant-54644949b7                 Created pod: qdrant-54644949b7-xdnjg
12m         Normal    Created             pod/qdrant-54644949b7-xdnjg                  Container created
12m         Normal    Pulled              pod/qdrant-54644949b7-xdnjg                  Container image "qdrant/qdrant:v1.17.1" already present on machine and can be accessed by the pod
12m         Normal    Scheduled           pod/qdrant-54644949b7-xdnjg                  Successfully assigned cognic-proofm85c/qdrant-54644949b7-xdnjg to cognic-proofm85c-control-plane
12m         Normal    ScalingReplicaSet   deployment/postgres                          Scaled up replica set postgres-74b77c4f75 from 0 to 1
12m         Normal    SuccessfulCreate    replicaset/postgres-74b77c4f75               Created pod: postgres-74b77c4f75-tfn6c
12m         Normal    Created             pod/postgres-74b77c4f75-tfn6c                Container created
12m         Normal    Pulled              pod/postgres-74b77c4f75-tfn6c                Container image "postgres:16-alpine" already present on machine and can be accessed by the pod
12m         Normal    Scheduled           pod/langfuse-77458bd486-pttl4                Successfully assigned cognic-proofm85c/langfuse-77458bd486-pttl4 to cognic-proofm85c-control-plane
12m         Normal    Scheduled           pod/postgres-74b77c4f75-tfn6c                Successfully assigned cognic-proofm85c/postgres-74b77c4f75-tfn6c to cognic-proofm85c-control-plane
12m         Normal    ScalingReplicaSet   deployment/ollama                            Scaled up replica set ollama-84dd449db5 from 0 to 1
12m         Normal    SuccessfulCreate    replicaset/ollama-84dd449db5                 Created pod: ollama-84dd449db5-b8j8j
12m         Normal    Scheduled           pod/ollama-84dd449db5-b8j8j                  Successfully assigned cognic-proofm85c/ollama-84dd449db5-b8j8j to cognic-proofm85c-control-plane
12m         Normal    ScalingReplicaSet   deployment/litellm                           Scaled up replica set litellm-854bfdcb5d from 0 to 1
12m         Normal    SuccessfulCreate    replicaset/vault-564b656fbf                  Created pod: vault-564b656fbf-zgnht
12m         Normal    SuccessfulCreate    replicaset/litellm-854bfdcb5d                Created pod: litellm-854bfdcb5d-rdv98
12m         Normal    SuccessfulCreate    replicaset/langfuse-77458bd486               Created pod: langfuse-77458bd486-pttl4
12m         Normal    ScalingReplicaSet   deployment/vault                             Scaled up replica set vault-564b656fbf from 0 to 1
12m         Normal    Scheduled           pod/litellm-854bfdcb5d-rdv98                 Successfully assigned cognic-proofm85c/litellm-854bfdcb5d-rdv98 to cognic-proofm85c-control-plane
12m         Normal    Started             pod/otel-collector-85ffcbbfcf-rpd24          Container started
12m         Normal    SuccessfulCreate    replicaset/otel-collector-85ffcbbfcf         Created pod: otel-collector-85ffcbbfcf-rpd24
12m         Normal    Started             pod/redis-74c49dd754-65sn7                   Container started
12m         Warning   Unhealthy           pod/postgres-74b77c4f75-tfn6c                Readiness probe failed: /var/run/postgresql:5432 - no response
12m         Normal    Scheduled           pod/cognic-proof-keycloak-555bf644d-wgds8    Successfully assigned cognic-proofm85c/cognic-proof-keycloak-555bf644d-wgds8 to cognic-proofm85c-control-plane
12m         Normal    SuccessfulCreate    replicaset/langfuse-7f9f57b4b                Created pod: langfuse-7f9f57b4b-2nqzc
12m         Normal    Started             pod/postgres-74b77c4f75-tfn6c                Container started
12m         Normal    ScalingReplicaSet   deployment/langfuse                          Scaled up replica set langfuse-7f9f57b4b from 0 to 1
12m         Normal    SuccessfulCreate    replicaset/cognic-proof-keycloak-555bf644d   Created pod: cognic-proof-keycloak-555bf644d-wgds8
12m         Normal    Scheduled           pod/langfuse-7f9f57b4b-2nqzc                 Successfully assigned cognic-proofm85c/langfuse-7f9f57b4b-2nqzc to cognic-proofm85c-control-plane
12m         Normal    Pulled              pod/litellm-854bfdcb5d-rdv98                 Container image "ghcr.io/berriai/litellm:main-stable" already present on machine and can be accessed by the pod
12m         Normal    Created             pod/litellm-854bfdcb5d-rdv98                 Container created
12m         Normal    Started             pod/litellm-854bfdcb5d-rdv98                 Container started
12m         Normal    ScalingReplicaSet   deployment/cognic-proof-keycloak             Scaled up replica set cognic-proof-keycloak-555bf644d from 0 to 1
12m         Normal    ScalingReplicaSet   deployment/otel-collector                    Scaled up replica set otel-collector-85ffcbbfcf from 0 to 1
12m         Normal    Pulling             pod/cognic-proof-keycloak-555bf644d-wgds8    Pulling image "keycloak/keycloak:26.2@sha256:4883630ef9db14031cde3e60700c9a9a8eaf1b5c24db1589d6a2d43de38ba2a9"
12m         Normal    Created             pod/redis-74c49dd754-65sn7                   Container created
12m         Normal    Created             pod/otel-collector-85ffcbbfcf-rpd24          Container created
12m         Normal    Pulled              pod/otel-collector-85ffcbbfcf-rpd24          Container image "otel/opentelemetry-collector:0.111.0" already present on machine and can be accessed by the pod
12m         Normal    Started             pod/qdrant-54644949b7-xdnjg                  Container started
12m         Normal    Pulled              pod/vault-564b656fbf-zgnht                   Container image "hashicorp/vault:1.18" already present on machine and can be accessed by the pod
12m         Warning   Unhealthy           pod/vault-564b656fbf-zgnht                   Readiness probe failed: Get "http://10.244.0.11:8200/v1/sys/health": dial tcp 10.244.0.11:8200: connect: connection refused
12m         Normal    Created             pod/vault-564b656fbf-zgnht                   Container created
12m         Normal    Pulled              pod/redis-74c49dd754-65sn7                   Container image "redis:7.4-alpine" already present on machine and can be accessed by the pod
12m         Warning   Unhealthy           pod/qdrant-54644949b7-xdnjg                  Readiness probe failed: Get "http://10.244.0.6:6333/readyz": dial tcp 10.244.0.6:6333: connect: connection refused
12m         Normal    Started             pod/vault-564b656fbf-zgnht                   Container started
12m         Normal    Scheduled           pod/otel-collector-85ffcbbfcf-rpd24          Successfully assigned cognic-proofm85c/otel-collector-85ffcbbfcf-rpd24 to cognic-proofm85c-control-plane
12m         Normal    Pulled              pod/ollama-84dd449db5-b8j8j                  Container image "ollama/ollama:0.5.4" already present on machine and can be accessed by the pod
12m         Normal    Created             pod/ollama-84dd449db5-b8j8j                  Container created
12m         Normal    Started             pod/ollama-84dd449db5-b8j8j                  Container started
12m         Warning   BackOff             pod/langfuse-77458bd486-pttl4                Back-off restarting failed container langfuse in pod langfuse-77458bd486-pttl4_cognic-proofm85c(1db0b189-f461-4660-aa1a-75641ffb8c37)
12m         Warning   BackOff             pod/langfuse-7f9f57b4b-2nqzc                 Back-off restarting failed container langfuse in pod langfuse-7f9f57b4b-2nqzc_cognic-proofm85c(8da87cca-fd03-4464-874f-2ed17f2d993c)
12m         Warning   Unhealthy           pod/litellm-854bfdcb5d-rdv98                 Readiness probe failed: Get "http://10.244.0.9:4000/health/liveliness": dial tcp 10.244.0.9:4000: connect: connection refused
12m         Normal    Pulled              pod/langfuse-77458bd486-pttl4                Container image "langfuse/langfuse:2" already present on machine and can be accessed by the pod
12m         Normal    Created             pod/langfuse-77458bd486-pttl4                Container created
12m         Normal    Started             pod/langfuse-77458bd486-pttl4                Container started
12m         Warning   Unhealthy           pod/langfuse-77458bd486-pttl4                Readiness probe failed: Get "http://10.244.0.8:3000/api/public/health": dial tcp 10.244.0.8:3000: connect: connection refused
12m         Normal    Pulled              pod/langfuse-7f9f57b4b-2nqzc                 Container image "langfuse/langfuse:2" already present on machine and can be accessed by the pod
12m         Normal    Created             pod/langfuse-7f9f57b4b-2nqzc                 Container created
12m         Normal    Started             pod/langfuse-7f9f57b4b-2nqzc                 Container started
12m         Warning   Unhealthy           pod/langfuse-7f9f57b4b-2nqzc                 Readiness probe failed: Get "http://10.244.0.14:3000/api/public/health": dial tcp 10.244.0.14:3000: connect: connection refused
12m         Warning   Unhealthy           pod/langfuse-77458bd486-pttl4                Readiness probe failed: HTTP probe failed with statuscode: 500
12m         Normal    Killing             pod/langfuse-77458bd486-pttl4                Stopping container langfuse
12m         Normal    SuccessfulDelete    replicaset/langfuse-77458bd486               Deleted pod: langfuse-77458bd486-pttl4
12m         Normal    ScalingReplicaSet   deployment/langfuse                          Scaled down replica set langfuse-77458bd486 from 1 to 0
12m         Normal    Pulled              pod/cognic-proof-keycloak-555bf644d-wgds8    Successfully pulled image "keycloak/keycloak:26.2@sha256:4883630ef9db14031cde3e60700c9a9a8eaf1b5c24db1589d6a2d43de38ba2a9" in 41.484s (41.484s including waiting). Image size: 244434445 bytes.
12m         Normal    Created             pod/cognic-proof-keycloak-555bf644d-wgds8    Container created
12m         Normal    Started             pod/cognic-proof-keycloak-555bf644d-wgds8    Container started
11m         Warning   Unhealthy           pod/cognic-proof-keycloak-555bf644d-wgds8    Readiness probe failed: dial tcp 10.244.0.13:8443: connect: connection refused
11m         Normal    Scheduled           pod/oracle-xe-6fbd6d88cc-z5tnc               Successfully assigned cognic-proofm85c/oracle-xe-6fbd6d88cc-z5tnc to cognic-proofm85c-control-plane
11m         Normal    ScalingReplicaSet   deployment/oracle-xe                         Scaled up replica set oracle-xe-6fbd6d88cc from 0 to 1
11m         Normal    SuccessfulCreate    replicaset/oracle-xe-6fbd6d88cc              Created pod: oracle-xe-6fbd6d88cc-z5tnc
11m         Normal    Pulled              pod/oracle-xe-6fbd6d88cc-z5tnc               Container image "gvenzl/oracle-xe:21-slim" already present on machine and can be accessed by the pod
11m         Normal    Started             pod/oracle-xe-6fbd6d88cc-z5tnc               Container started
11m         Normal    Created             pod/oracle-xe-6fbd6d88cc-z5tnc               Container created
10m         Normal    Scheduled           pod/agentos-migrate-dbqzt                    Successfully assigned cognic-proofm85c/agentos-migrate-dbqzt to cognic-proofm85c-control-plane
10m         Normal    Scheduled           pod/rel-agentos-577f67f98b-hdpz2             Successfully assigned cognic-proofm85c/rel-agentos-577f67f98b-hdpz2 to cognic-proofm85c-control-plane
10m         Normal    SuccessfulCreate    replicaset/rel-agentos-577f67f98b            Created pod: rel-agentos-577f67f98b-hdpz2
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled up replica set rel-agentos-577f67f98b from 0 to 1
10m         Normal    SuccessfulCreate    job/agentos-migrate                          Created pod: agentos-migrate-dbqzt
10m         Normal    Created             pod/agentos-migrate-dbqzt                    Container created
10m         Normal    Started             pod/agentos-migrate-dbqzt                    Container started
10m         Normal    Pulled              pod/agentos-migrate-dbqzt                    Container image "cognic-agentos:proofm85c" already present on machine and can be accessed by the pod
10m         Normal    Created             pod/rel-agentos-577f67f98b-hdpz2             Container created
10m         Normal    Started             pod/rel-agentos-577f67f98b-hdpz2             Container started
10m         Normal    Pulled              pod/rel-agentos-577f67f98b-hdpz2             Container image "cognic-agentos:proofm85c" already present on machine and can be accessed by the pod
10m         Warning   BackOff             pod/rel-agentos-577f67f98b-hdpz2             Back-off restarting failed container agentos in pod rel-agentos-577f67f98b-hdpz2_cognic-proofm85c(0289f616-b965-49c0-aa34-bff053404b60)
10m         Normal    Completed           job/agentos-migrate                          Job completed
10m         Normal    Created             pod/proof-as-668846b487-z22q7                Container created
10m         Normal    Started             pod/proof-as-668846b487-z22q7                Container started
10m         Normal    SuccessfulCreate    replicaset/proof-oracle-pack-8bdc7c4f6       Created pod: proof-oracle-pack-8bdc7c4f6-cc5mf
10m         Normal    Started             pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Container started
10m         Normal    Created             pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Container created
10m         Normal    Pulled              pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Container image "cognic-proof-oracle-pack:m85" already present on machine and can be accessed by the pod
10m         Normal    Started             pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Container started
10m         Normal    Created             pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Container created
10m         Normal    Pulled              pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Container image "busybox:1.36" already present on machine and can be accessed by the pod
10m         Normal    Scheduled           pod/proof-oracle-pack-8bdc7c4f6-cc5mf        Successfully assigned cognic-proofm85c/proof-oracle-pack-8bdc7c4f6-cc5mf to cognic-proofm85c-control-plane
10m         Normal    ScalingReplicaSet   deployment/proof-as                          Scaled up replica set proof-as-668846b487 from 0 to 1
10m         Normal    ScalingReplicaSet   deployment/proof-oracle-pack                 Scaled up replica set proof-oracle-pack-8bdc7c4f6 from 0 to 1
10m         Normal    Scheduled           pod/proof-as-668846b487-z22q7                Successfully assigned cognic-proofm85c/proof-as-668846b487-z22q7 to cognic-proofm85c-control-plane
10m         Normal    Pulled              pod/proof-as-668846b487-z22q7                Container image "cognic-proof-as:m85" already present on machine and can be accessed by the pod
10m         Normal    SuccessfulCreate    replicaset/proof-as-668846b487               Created pod: proof-as-668846b487-z22q7
10m         Normal    ScalingReplicaSet   deployment/litellm                           Scaled up replica set litellm-c897555d from 0 to 1
10m         Normal    Pulled              pod/litellm-c897555d-ldtpx                   Container image "ghcr.io/berriai/litellm:main-stable" already present on machine and can be accessed by the pod
10m         Normal    SuccessfulCreate    replicaset/rel-agentos-575dfb5f9f            Created pod: rel-agentos-575dfb5f9f-v57n2
10m         Normal    SuccessfulCreate    replicaset/rel-agentos-bf64f5589             Created pod: rel-agentos-bf64f5589-fb9gx
10m         Normal    Scheduled           pod/rel-agentos-575dfb5f9f-v57n2             Successfully assigned cognic-proofm85c/rel-agentos-575dfb5f9f-v57n2 to cognic-proofm85c-control-plane
10m         Normal    SuccessfulDelete    replicaset/rel-agentos-577f67f98b            Deleted pod: rel-agentos-577f67f98b-hdpz2
10m         Normal    Scheduled           pod/rel-agentos-5d59c8cfb8-jpqdw             Successfully assigned cognic-proofm85c/rel-agentos-5d59c8cfb8-jpqdw to cognic-proofm85c-control-plane
10m         Normal    Pulled              pod/rel-agentos-5d59c8cfb8-jpqdw             Container image "busybox:1.36" already present on machine and can be accessed by the pod
10m         Normal    Created             pod/rel-agentos-5d59c8cfb8-jpqdw             Container created
10m         Normal    Started             pod/rel-agentos-5d59c8cfb8-jpqdw             Container started
10m         Normal    SuccessfulCreate    replicaset/litellm-c897555d                  Created pod: litellm-c897555d-ldtpx
10m         Normal    Started             pod/litellm-c897555d-ldtpx                   Container started
10m         Normal    Created             pod/litellm-c897555d-ldtpx                   Container created
10m         Normal    SuccessfulDelete    replicaset/rel-agentos-575dfb5f9f            Deleted pod: rel-agentos-575dfb5f9f-v57n2
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled up replica set rel-agentos-5d59c8cfb8 from 0 to 1
10m         Normal    SuccessfulCreate    replicaset/rel-agentos-5d59c8cfb8            Created pod: rel-agentos-5d59c8cfb8-jpqdw
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled down replica set rel-agentos-575dfb5f9f from 1 to 0
10m         Normal    Scheduled           pod/rel-agentos-bf64f5589-fb9gx              Successfully assigned cognic-proofm85c/rel-agentos-bf64f5589-fb9gx to cognic-proofm85c-control-plane
10m         Normal    Pulled              pod/rel-agentos-bf64f5589-fb9gx              Container image "busybox:1.36" already present on machine and can be accessed by the pod
10m         Normal    Created             pod/rel-agentos-bf64f5589-fb9gx              Container created
10m         Normal    Started             pod/rel-agentos-bf64f5589-fb9gx              Container started
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled up replica set rel-agentos-575dfb5f9f from 0 to 1
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled down replica set rel-agentos-577f67f98b from 1 to 0
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled up replica set rel-agentos-bf64f5589 from 0 to 1
10m         Normal    Scheduled           pod/litellm-c897555d-ldtpx                   Successfully assigned cognic-proofm85c/litellm-c897555d-ldtpx to cognic-proofm85c-control-plane
10m         Normal    Started             pod/rel-agentos-5d59c8cfb8-jpqdw             Container started
10m         Normal    Pulled              pod/rel-agentos-5d59c8cfb8-jpqdw             Container image "cognic-agentos:proofm85c" already present on machine and can be accessed by the pod
10m         Normal    Created             pod/rel-agentos-5d59c8cfb8-jpqdw             Container created
10m         Warning   Unhealthy           pod/litellm-c897555d-ldtpx                   Readiness probe failed: Get "http://10.244.0.22:4000/health/liveliness": dial tcp 10.244.0.22:4000: connect: connection refused
10m         Warning   Unhealthy           pod/rel-agentos-bf64f5589-fb9gx              Startup probe failed: Get "https://10.244.0.20:8443/api/v1/healthz": dial tcp 10.244.0.20:8443: connect: connection refused
10m         Warning   Unhealthy           pod/rel-agentos-5d59c8cfb8-jpqdw             Startup probe failed: Get "https://10.244.0.21:8443/api/v1/healthz": dial tcp 10.244.0.21:8443: connect: connection refused
10m         Normal    Killing             pod/litellm-854bfdcb5d-rdv98                 Stopping container litellm
10m         Normal    SuccessfulDelete    replicaset/litellm-854bfdcb5d                Deleted pod: litellm-854bfdcb5d-rdv98
10m         Normal    ScalingReplicaSet   deployment/litellm                           Scaled down replica set litellm-854bfdcb5d from 1 to 0
10m         Normal    Pulled              pod/rel-agentos-c796b8c9f-xg47s              Container image "cognic-agentos:proofm85c" already present on machine and can be accessed by the pod
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled down replica set rel-agentos-5d59c8cfb8 from 1 to 0
10m         Normal    Created             pod/rel-agentos-c796b8c9f-xg47s              Container created
10m         Normal    SuccessfulCreate    replicaset/rel-agentos-c796b8c9f             Created pod: rel-agentos-c796b8c9f-xg47s
10m         Normal    Created             pod/rel-agentos-c796b8c9f-xg47s              Container created
10m         Normal    Started             pod/rel-agentos-c796b8c9f-xg47s              Container started
10m         Normal    Scheduled           pod/rel-agentos-c796b8c9f-xg47s              Successfully assigned cognic-proofm85c/rel-agentos-c796b8c9f-xg47s to cognic-proofm85c-control-plane
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled up replica set rel-agentos-c796b8c9f from 0 to 1
10m         Normal    SuccessfulDelete    replicaset/rel-agentos-5d59c8cfb8            Deleted pod: rel-agentos-5d59c8cfb8-jpqdw
10m         Normal    Killing             pod/rel-agentos-5d59c8cfb8-jpqdw             Stopping container agentos
10m         Normal    Pulled              pod/rel-agentos-c796b8c9f-xg47s              Container image "busybox:1.36" already present on machine and can be accessed by the pod
10m         Normal    Started             pod/rel-agentos-c796b8c9f-xg47s              Container started
10m         Warning   BackOff             pod/rel-agentos-bf64f5589-fb9gx              Back-off restarting failed container agentos in pod rel-agentos-bf64f5589-fb9gx_cognic-proofm85c(3d9262f8-949a-480f-85e8-afc1125f9c20)
10m         Warning   Unhealthy           pod/rel-agentos-c796b8c9f-xg47s              Startup probe failed: Get "https://10.244.0.23:8443/api/v1/healthz": dial tcp 10.244.0.23:8443: connect: connection refused
10m         Normal    Pulled              pod/rel-agentos-bf64f5589-fb9gx              Container image "cognic-agentos:proofm85c" already present on machine and can be accessed by the pod
10m         Normal    Created             pod/rel-agentos-bf64f5589-fb9gx              Container created
10m         Normal    Started             pod/rel-agentos-bf64f5589-fb9gx              Container started
10m         Normal    Killing             pod/rel-agentos-bf64f5589-fb9gx              Stopping container agentos
10m         Normal    SuccessfulDelete    replicaset/rel-agentos-bf64f5589             Deleted pod: rel-agentos-bf64f5589-fb9gx
10m         Normal    ScalingReplicaSet   deployment/rel-agentos                       Scaled down replica set rel-agentos-bf64f5589 from 1 to 0
```

## Proof M8.5-C attempt 6 — dependency-resolution FAILURE (2026-07-14T01:09:19Z)

- **Result:** exit 1 before cluster creation, Step 0a, Bars A-F, or any model call.
  The only provider request was the zero-spend `GET /v1/models` key preflight (HTTP
  200).
- **Passed before the halt:** proof-input cleanliness; all released-pack digests;
  release-signature verification; proof-local cosign v3 re-signing; query-context,
  TLS, Keycloak-realm, and approval-key generation; clean kernel provenance at
  `6a762c2db5537276be369608da83a7d0a1961c07`.
- **Failure:** all three bounded Docker build attempts failed while the proof image
  executed `pip install "aiodocker>=0.24"`; Docker's bridge resolver could not resolve
  `files.pythonhosted.org` although host networking could retrieve the exact locked
  wheel.
- **Finding:** the proof Dockerfile bypassed the committed `uv.lock` (which pins
  `aiodocker==0.26.0`) and asked live PyPI to select a floating version (the failed
  attempt selected 0.27.0). This was both an environmental failure surface and a
  reproducibility defect.
- **Remediation posture:** the proof base opts into the existing `sandbox-docker`
  extra through a proof-only build argument; `uv sync --frozen` owns resolution, the
  production default remains unchanged, and the derived proof image performs only an
  import check. The two networked proof builds use host networking to avoid the
  Docker Desktop bridge-DNS failure while retaining lock/digest verification.
- **Operator log:** 378 lines, SHA-256
  `183dabfb02413e9713fd19f1613817e6641fb9b63b3e62249ffa56679dcf0bfa`
  (`/tmp/proof-m85c.log`, operator-held and not committed).

## Proof M8.5-C attempt 7 — image-fetch FAILURE (2026-07-14)

- **Result:** exit 1 before cluster creation, Step 0a, Bars A-F, or any model
  call. The provider key passed only the zero-spend `GET /v1/models` preflight.
- **Passed before the halt:** released-pack digest and signature verification,
  proof-local cosign signing, per-run key/PKI/realm generation, and clean kernel
  provenance at `0cc482e59b1303dee1473457e233c48517871573`.
- **Failure:** Docker Desktop's resolver first failed registry/Astral lookups.
  After the host environment was repaired, the exact final base build proved
  the attempt-6 fix live (`aiodocker==0.26.0`, `aiohttp==3.13.5`, both from the
  frozen lock) but BuildKit repeatedly received a TLS EOF from the
  `openpolicyagent.org` vanity download hop. The same checksum-pinned asset was
  reachable through its canonical GitHub release URL.
- **Remediation posture:** retain the pinned OPA version and SHA-256, fetch the
  artifact directly from the canonical GitHub release, and permanently forbid
  the redirecting vanity URL in the binary-pin suite. No hostname/IP override
  is embedded in source.
- **Operator log:** 194 lines, SHA-256
  `dab2e11191a868da0ddef281e1d59bccd3fecfc00f7e53561e1722a0ef3b2750`
  (`/tmp/proof-m85c.log`, operator-held and not committed). The log captures
  the runner's DNS abort; the exact-build OPA diagnosis followed interactively.

## Proof M8.5 slice — FAILURE (2026-07-14T02:37:04Z)

- Failed step: `SETUP 8 no derived allow-list row (got: allowlist|proof-m85c|10.96.0.51|https://cognic-proof-keycloak:8443/realms/proof-m85c#13bbe635-24ef-5421-a15f-8f1bbc4607cf
override|proof-m85c|cognic-tool-oracle-schema|http://10.96.0.51:8765/mcp)`
- last API response (HTTP 200):
```json
{"id":"6a0d4269-3fb1-42ed-be5a-8d88fe168df0","kind":"tool","pack_id":"cognic-tool-oracle-schema","display_name":"Cognic Oracle Schema (proof-m85c)","state":"installed","tenant_id":"proof-m85c","created_by":"https://cognic-proof-keycloak:8443/realms/proof-m85c#4ef652ed-afff-514b-ab29-bda01f609ad5","last_actor":"https://cognic-proof-keycloak:8443/realms/proof-m85c#13bbe635-24ef-5421-a15f-8f1bbc4607cf","created_at":"2026-07-14T02:37:02.117791Z","updated_at":"2026-07-14T02:37:03.293117Z"}
```
- conversation.% chain rows (tail 10 — digest-only):
```
<none>
```
- conversations operational records (tail 6 — no plaintext):
```
<none>
```
- agent / dispatch / gateway reason markers:
```
<none captured>
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
<none>
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
<none>
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m02:36:25 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m02:36:25 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#               'A feature I really want is...'               #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:41820 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51180 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36110 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35582 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
<none>
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"2372b5bfdf3e8455ea42f67f09b316153e7489a59a2ab35bba4087ee2f2cf8a3","refusal_reason":null,"registered_at":"2026-07-14T02:36:33.789839+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"63ecc1eea2e23bee5256b159d9bb076faa90022b78013f937a36b2c6f0e1099f","refusal_reason":null,"registered_at":"2026-07-14T02:36:33.982452+00:00","discovery_status":"unprobed"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T02:36:34.179486+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T02:36:34.370555+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T02:36:34.571167+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T02:36:34.773648+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T02:36:34.971047+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T02:36:35.168825+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T02:36:35.366899+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":9,"auth_ready":0,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : 955693cf1ebcb538
    ID             : 98f2b788f07d07a1
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 02:36:58.269885844 +0000 UTC
    End time       : 2026-07-14 02:36:58.269916136 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #5
    Trace ID       : a500ffd65ce15910ce2496dc89875b1c
    Parent ID      : 955693cf1ebcb538
    ID             : 81e96ab7c0e1438b
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 02:36:58.270045136 +0000 UTC
    End time       : 2026-07-14 02:36:58.270051261 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #6
    Trace ID       : a500ffd65ce15910ce2496dc89875b1c
    Parent ID      : 955693cf1ebcb538
    ID             : b80a39cab0551b8b
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 02:36:58.270077219 +0000 UTC
    End time       : 2026-07-14 02:36:58.270082011 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #7
    Trace ID       : a500ffd65ce15910ce2496dc89875b1c
    Parent ID      :
    ID             : 955693cf1ebcb538
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-14 02:36:58.248743594 +0000 UTC
    End time       : 2026-07-14 02:36:58.270141386 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.23:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.23:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.23:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(54850)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 02:36:33,078", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 02:36:35,835", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 02:36:37,780", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1707f85676764cbb9bee08a43f5d4208", "trace_id": "fb70e7febfa017379a138313f4be573f", "span_id": "3cb16184c771ff48", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.585, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:36:38,248", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-412db11fe2cc4f49aafb49a49f427f3e", "trace_id": "ab5c7d490adc5a5121afdcd02bf3135e", "span_id": "c0c6e647b65af91d"}
{"ts": "2026-07-14 02:36:38,258", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-412db11fe2cc4f49aafb49a49f427f3e", "trace_id": "ab5c7d490adc5a5121afdcd02bf3135e", "span_id": "c0c6e647b65af91d"}
{"ts": "2026-07-14 02:36:38,266", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-412db11fe2cc4f49aafb49a49f427f3e", "trace_id": "ab5c7d490adc5a5121afdcd02bf3135e", "span_id": "c0c6e647b65af91d"}
{"ts": "2026-07-14 02:36:38,266", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-412db11fe2cc4f49aafb49a49f427f3e", "trace_id": "ab5c7d490adc5a5121afdcd02bf3135e", "span_id": "c0c6e647b65af91d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.579, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:36:39,353", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-df5a3ebacf12451bb8ba5b28c7a2ad85", "trace_id": "f23f753d61a1b64934e4420abff86ede", "span_id": "d27b3601ca9bcb73", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.109, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:36:42,308", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0869ded10df241ff8b29619deada5f4e", "trace_id": "c2a7408f4f91f937953103898e0998a4", "span_id": "bffc6ad6fa946829", "http_method": "GET", "http_path": "/api/v1/system/plugins", "http_has_query": true, "http_query_param_count": 1, "http_status_code": 200, "duration_ms": 0.841, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:36:42,404", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-56879081601f4a6a84306c915ac8743f", "trace_id": "32ab469423427b29409a8d9287485d45", "span_id": "1267e57cae74187a", "http_method": "GET", "http_path": "/api/v1/system/plugins", "http_has_query": true, "http_query_param_count": 1, "http_status_code": 200, "duration_ms": 0.209, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:36:42,769", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-cd1688aa6dc14fe18e321900edcf81ff", "trace_id": "ef230103d2c7e98dd86ec48259656c09", "span_id": "0a03cd8ee84dda99", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.098, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:36:48,247", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0a8f1f93d17d4a34aff158865355211b", "trace_id": "a8c6273e4f46b901853a4d341e9eedb0", "span_id": "888b8b78034e027d"}
{"ts": "2026-07-14 02:36:48,257", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0a8f1f93d17d4a34aff158865355211b", "trace_id": "a8c6273e4f46b901853a4d341e9eedb0", "span_id": "888b8b78034e027d"}
{"ts": "2026-07-14 02:36:48,267", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0a8f1f93d17d4a34aff158865355211b", "trace_id": "a8c6273e4f46b901853a4d341e9eedb0", "span_id": "888b8b78034e027d"}
{"ts": "2026-07-14 02:36:48,267", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0a8f1f93d17d4a34aff158865355211b", "trace_id": "a8c6273e4f46b901853a4d341e9eedb0", "span_id": "888b8b78034e027d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.249, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:36:57,773", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-85296f20f80b4315aa5628cec1f5f6c3", "trace_id": "c45726ce511fa27983e14ae5992853ba", "span_id": "c2c23c0c11456e82", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.222, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:36:58,251", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b1a3c3ba98bd4f3699f2f3f5f738592b", "trace_id": "a500ffd65ce15910ce2496dc89875b1c", "span_id": "955693cf1ebcb538"}
{"ts": "2026-07-14 02:36:58,260", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b1a3c3ba98bd4f3699f2f3f5f738592b", "trace_id": "a500ffd65ce15910ce2496dc89875b1c", "span_id": "955693cf1ebcb538"}
{"ts": "2026-07-14 02:36:58,269", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b1a3c3ba98bd4f3699f2f3f5f738592b", "trace_id": "a500ffd65ce15910ce2496dc89875b1c", "span_id": "955693cf1ebcb538"}
{"ts": "2026-07-14 02:36:58,269", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b1a3c3ba98bd4f3699f2f3f5f738592b", "trace_id": "a500ffd65ce15910ce2496dc89875b1c", "span_id": "955693cf1ebcb538", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.619, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:37:02,139", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-df79e8c838244a18b38422030f53c70c", "trace_id": "dddcd5ec370e97fdfcbe32f34c9293b1", "span_id": "96f90f85c2bcf4df", "http_method": "POST", "http_path": "/api/v1/packs/drafts", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 25.467, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:37:02,424", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5ddae63e2af44dfdad566b6d4c1fa151", "trace_id": "d1194a577d70d0623136a88c4b0a2788", "span_id": "eaab237221d67acd", "http_method": "POST", "http_path": "/api/v1/packs/drafts/6a0d4269-3fb1-42ed-be5a-8d88fe168df0/submit", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.0, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:37:02,651", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-cb2137f794084af4979038580b65b6bd", "trace_id": "bc4ea391f5ed7a1767764c683e986a8a", "span_id": "8116b2f2a3f91e81", "http_method": "POST", "http_path": "/api/v1/packs/6a0d4269-3fb1-42ed-be5a-8d88fe168df0/claim", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 6.225, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:37:02,930", "level": "WARNING", "logger": "cognic_agentos.portal.api.packs.review_routes", "message": "portal.packs.approve_overridden", "request_id": "portal-req-6a4fd02b6dc44f039c98f1443fcc5758", "trace_id": "9b0f4bbbaacc16f83b213603f29b29d7", "span_id": "19c9dca57d5b161a", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#53cf5f16-efd4-5ae5-ae59-850959b80542", "pack_id": "6a0d4269-3fb1-42ed-be5a-8d88fe168df0", "override_reason": "prerelease_validation", "override_event_id": "cd70ea1d-2bb5-4a48-a59d-4fab9f5fd234"}
{"ts": "2026-07-14 02:37:02,931", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-6a4fd02b6dc44f039c98f1443fcc5758", "trace_id": "9b0f4bbbaacc16f83b213603f29b29d7", "span_id": "19c9dca57d5b161a", "http_method": "POST", "http_path": "/api/v1/packs/6a0d4269-3fb1-42ed-be5a-8d88fe168df0/approve", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 205.847, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:37:03,153", "level": "WARNING", "logger": "cognic_agentos.portal.api.packs.operator_routes", "message": "portal.packs.allow_list", "request_id": "portal-req-91e1eaf0254247a0b036cc97c34c33a8", "trace_id": "171fe283f1fce5e6fb605720487b4a04", "span_id": "db8c1f59eeb58e34", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#13bbe635-24ef-5421-a15f-8f1bbc4607cf", "actor_type": "human", "pack_id": "6a0d4269-3fb1-42ed-be5a-8d88fe168df0"}
{"ts": "2026-07-14 02:37:03,154", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-91e1eaf0254247a0b036cc97c34c33a8", "trace_id": "171fe283f1fce5e6fb605720487b4a04", "span_id": "db8c1f59eeb58e34", "http_method": "POST", "http_path": "/api/v1/packs/6a0d4269-3fb1-42ed-be5a-8d88fe168df0/allow-list", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 7.124, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:37:03,237", "level": "WARNING", "logger": "cognic_agentos.portal.api.packs.configure_routes", "message": "portal.packs.configure_set", "request_id": "portal-req-334421f2f5614953bbe07bbd74e928b1", "trace_id": "80087e4bc41af4f5fb1315fb4b1cfe96", "span_id": "918e6aea1e76849b", "tenant_id": "proof-m85c", "pack_id": "6a0d4269-3fb1-42ed-be5a-8d88fe168df0", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#13bbe635-24ef-5421-a15f-8f1bbc4607cf", "actor_type": "human"}
{"ts": "2026-07-14 02:37:03,238", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-334421f2f5614953bbe07bbd74e928b1", "trace_id": "80087e4bc41af4f5fb1315fb4b1cfe96", "span_id": "918e6aea1e76849b", "http_method": "PUT", "http_path": "/api/v1/packs/6a0d4269-3fb1-42ed-be5a-8d88fe168df0/runtime-config", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 9.803, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:37:03,313", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5f3f639f5de04729951839572e2a0afd", "trace_id": "f2b8697cafc02986b67ac46e631da148", "span_id": "136885683debe236", "http_method": "POST", "http_path": "/api/v1/packs/6a0d4269-3fb1-42ed-be5a-8d88fe168df0/install", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.047, "client_addr": "127.0.0.1"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T02:57:54Z)

- Failed step: `PROBE SETUP warm-up list_tools (HTTP 502 — probe carve-out not live?)`
- last API response (HTTP 502):
```json
{"detail":{"reason":"mcp_as_not_allowlisted"}}
```
- conversation.% chain rows (tail 10 — digest-only):
```
<none>
```
- conversations operational records (tail 6 — no plaintext):
```
<none>
```
- agent / dispatch / gateway reason markers:
```
<none captured>
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
<none>
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
<none>
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m02:56:50 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m02:56:50 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#              'I don't like how this works...'               #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:39082 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:52418 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33912 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33574 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:43202 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:34150 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47136 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
<none>
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"8864986cdc606db3c545f2363961e6f69b03ba504b90a97018147207919725f8","refusal_reason":null,"registered_at":"2026-07-14T02:57:47.734323+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"be34af4ebfc4fc6c42e3a946c3de2c3ec5c4cd706e6a262ec191da3c8dc601d5","refusal_reason":null,"registered_at":"2026-07-14T02:57:47.934810+00:00","discovery_status":"refused"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T02:57:48.132320+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T02:57:48.329478+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T02:57:48.530237+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T02:57:48.728363+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T02:57:48.924806+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T02:57:49.121634+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T02:57:49.315716+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":0,"refused":1,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : dc9962babcbb7e9a
    ID             : 7b92389c1f25bf40
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 02:57:48.404011131 +0000 UTC
    End time       : 2026-07-14 02:57:48.40403634 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #1
    Trace ID       : 6cb4b8a371af8159e7e9a077ff2fb005
    Parent ID      : dc9962babcbb7e9a
    ID             : ff28332db4bff272
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 02:57:48.404169881 +0000 UTC
    End time       : 2026-07-14 02:57:48.404196965 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #2
    Trace ID       : 6cb4b8a371af8159e7e9a077ff2fb005
    Parent ID      : dc9962babcbb7e9a
    ID             : 30e396b589b22494
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 02:57:48.404234215 +0000 UTC
    End time       : 2026-07-14 02:57:48.404239048 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #3
    Trace ID       : 6cb4b8a371af8159e7e9a077ff2fb005
    Parent ID      :
    ID             : dc9962babcbb7e9a
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-14 02:57:48.382418006 +0000 UTC
    End time       : 2026-07-14 02:57:48.404299506 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.27:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.27:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.27:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(55438)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 02:57:47,013", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 02:57:49,784", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 02:57:51,988", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5d51298ea8e742da8fdfa3394ab8c04d", "trace_id": "5fc241b854be287887689ae141cdab8f", "span_id": "8d05a336e944dd93", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.584, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:57:52,430", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-621bd18ed047437487dcc7fb766a7bf1", "trace_id": "ec9a8b7475d7197e10e84866bf22a833", "span_id": "27bc6072fb0de8c1"}
{"ts": "2026-07-14 02:57:52,440", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-621bd18ed047437487dcc7fb766a7bf1", "trace_id": "ec9a8b7475d7197e10e84866bf22a833", "span_id": "27bc6072fb0de8c1"}
{"ts": "2026-07-14 02:57:52,448", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-621bd18ed047437487dcc7fb766a7bf1", "trace_id": "ec9a8b7475d7197e10e84866bf22a833", "span_id": "27bc6072fb0de8c1"}
{"ts": "2026-07-14 02:57:52,448", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-621bd18ed047437487dcc7fb766a7bf1", "trace_id": "ec9a8b7475d7197e10e84866bf22a833", "span_id": "27bc6072fb0de8c1", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.392, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 02:57:53,529", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-61363af81f3d4b029a7b2e5cc9f152c8", "trace_id": "01599751132e2f60761ad812be5ee686", "span_id": "035e196fe5b90803", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.118, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 02:57:53,587", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 401 Unauthorized\"", "request_id": "portal-req-1e428a1031b343dfa951f615ba7222a9", "trace_id": "24fcd2285c96c7227440d0a3bad6f7ea", "span_id": "ba32bf908e83e272"}
{"ts": "2026-07-14 02:57:53,590", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/.well-known/oauth-protected-resource/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1e428a1031b343dfa951f615ba7222a9", "trace_id": "24fcd2285c96c7227440d0a3bad6f7ea", "span_id": "ba32bf908e83e272"}
{"ts": "2026-07-14 02:57:53,591", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1e428a1031b343dfa951f615ba7222a9", "trace_id": "24fcd2285c96c7227440d0a3bad6f7ea", "span_id": "ba32bf908e83e272", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 502, "duration_ms": 14.631, "client_addr": "127.0.0.1"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T03:14:01Z)

- Failed step: `BAR A S8 cookie content (rc=1):   File "<string>", line 8
    f"__Host-cognic_session flags wrong: secure={sess[\"secure\"]!r} httpOnly={sess[\"httpOnly\"]!r}"
                                                       ^
SyntaxError: unexpected character after line continuation character`
- last API response (HTTP 200):
```json
{"tools":[{"name":"probe_write","title":null,"description":"Append a per-call nonce to the proof-local invocation ledger and return the nonce plus the ledger line count. Business-side-effect-free: the ledger is proof instrumentation for the ADR-014 four-eyes approval proof (the independent observer that makes 'zero execution' provable), not a business write.","inputSchema":{"properties":{"nonce":{"title":"Nonce","type":"string"}},"required":["nonce"],"title":"probe_writeArguments","type":"object"},"outputSchema":{"additionalProperties":true,"title":"probe_writeDictOutput","type":"object"},"icons":null,"annotations":null,"_meta":null,"execution":null}]}
```
- conversation.% chain rows (tail 10 — digest-only):
```
<none>
```
- conversations operational records (tail 6 — no plaintext):
```
<none>
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
<none>
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
<none>
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m03:12:46 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m03:12:46 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#           'I get frustrated when the product...'            #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:50876 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:38962 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:43566 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:37532 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55020 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57474 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46812 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:41088 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
<none>
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"6e5d1a94501270b6f4cb3da399af6dcc6a03934b53d57aca09b0c4a9afe4a42b","refusal_reason":null,"registered_at":"2026-07-14T03:13:45.412378+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"fe4ae63bbb58f84a0226124e1ae966fb6a310350f0ec2bfabe87c062baf012c1","refusal_reason":null,"registered_at":"2026-07-14T03:13:45.618524+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T03:13:45.825629+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T03:13:46.023995+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T03:13:46.224890+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T03:13:46.424240+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T03:13:46.717377+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T03:13:46.919018+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T03:13:47.118810+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : d2898bf15d7dbe47
    ID             : 75f75c564aafa0cd
    Name           : GET /api/v1/healthz http send
    Kind           : Internal
    Start time     : 2026-07-14 03:13:54.484403217 +0000 UTC
    End time       : 2026-07-14 03:13:54.484466676 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #1
    Trace ID       : 6917cf2861cb03079229bd7c21c884e8
    Parent ID      : d2898bf15d7dbe47
    ID             : 3bc03d87c3da7782
    Name           : GET /api/v1/healthz http send
    Kind           : Internal
    Start time     : 2026-07-14 03:13:54.484865676 +0000 UTC
    End time       : 2026-07-14 03:13:54.484890551 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #2
    Trace ID       : 6917cf2861cb03079229bd7c21c884e8
    Parent ID      : d2898bf15d7dbe47
    ID             : fdb54c24ef05b0f5
    Name           : GET /api/v1/healthz http send
    Kind           : Internal
    Start time     : 2026-07-14 03:13:54.484994176 +0000 UTC
    End time       : 2026-07-14 03:13:54.485006967 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #3
    Trace ID       : 6917cf2861cb03079229bd7c21c884e8
    Parent ID      :
    ID             : d2898bf15d7dbe47
    Name           : GET /api/v1/healthz
    Kind           : Server
    Start time     : 2026-07-14 03:13:54.483136176 +0000 UTC
    End time       : 2026-07-14 03:13:54.485137051 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/healthz)
     -> http.url: Str(https://10.244.0.29:8443/api/v1/healthz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.29:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(51704)
     -> http.route: Str(/api/v1/healthz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 03:13:44,659", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 03:13:47,593", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 03:13:49,490", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9add8768e87146f580ca65a521a3f182", "trace_id": "75d91ecba87333cf5df9bda731c79be1", "span_id": "bebb416c4b83801d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.552, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:13:49,944", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-82dac4ad581c4630a28e0e3ffd3e8413", "trace_id": "4df0e1885e8bf296fb5af5404c3da85f", "span_id": "f7b827f3b8bca4ce"}
{"ts": "2026-07-14 03:13:49,955", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-82dac4ad581c4630a28e0e3ffd3e8413", "trace_id": "4df0e1885e8bf296fb5af5404c3da85f", "span_id": "f7b827f3b8bca4ce"}
{"ts": "2026-07-14 03:13:49,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-82dac4ad581c4630a28e0e3ffd3e8413", "trace_id": "4df0e1885e8bf296fb5af5404c3da85f", "span_id": "f7b827f3b8bca4ce"}
{"ts": "2026-07-14 03:13:49,964", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-82dac4ad581c4630a28e0e3ffd3e8413", "trace_id": "4df0e1885e8bf296fb5af5404c3da85f", "span_id": "f7b827f3b8bca4ce", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.034, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:13:51,038", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e847197c8cf848689523027900ab7edb", "trace_id": "fc680d1d8368d8e6cd00a929eb29a085", "span_id": "6f01414ea7c6448d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.108, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 03:13:51,096", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 401 Unauthorized\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,101", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/.well-known/oauth-protected-resource/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,106", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://192.88.99.9:9000/.well-known/oauth-authorization-server \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,107", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://192.88.99.9:9000/token \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,298", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,298", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Received session ID: e7238ec991a84e509fbad9e83a1ea6ca", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,298", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Negotiated protocol version: 2025-11-25", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,301", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 202 Accepted\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,302", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,304", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,306", "level": "INFO", "logger": "httpx", "message": "HTTP Request: DELETE http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,306", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "GET stream disconnected, reconnecting in 1000ms...", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589"}
{"ts": "2026-07-14 03:13:51,306", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-23a3f5061781474a8e7de0aebd569537", "trace_id": "b1bd34579ff31d8a6ccb15de8ff32b96", "span_id": "c2f0d6568755b589", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 220.798, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 03:13:54,483", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-59772358cd304af8a4756ed9b1476806", "trace_id": "6917cf2861cb03079229bd7c21c884e8", "span_id": "d2898bf15d7dbe47", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.228, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:13:58,231", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ced937d1998b4d30b2b7ad09e86cb03e", "trace_id": "5bf1abd11f5d1e71890ab7438b8a48b6", "span_id": "456d7660f24589f0", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:13:58,232", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ced937d1998b4d30b2b7ad09e86cb03e", "trace_id": "5bf1abd11f5d1e71890ab7438b8a48b6", "span_id": "456d7660f24589f0", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 4.553, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 03:13:59,939", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-eab2a56504a744c28b85c084cf1ced16", "trace_id": "de74f802d1e080066a9e9a141467e915", "span_id": "34e62201eade6a8e"}
{"ts": "2026-07-14 03:13:59,948", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-eab2a56504a744c28b85c084cf1ced16", "trace_id": "de74f802d1e080066a9e9a141467e915", "span_id": "34e62201eade6a8e"}
{"ts": "2026-07-14 03:13:59,957", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-eab2a56504a744c28b85c084cf1ced16", "trace_id": "de74f802d1e080066a9e9a141467e915", "span_id": "34e62201eade6a8e"}
{"ts": "2026-07-14 03:13:59,958", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-eab2a56504a744c28b85c084cf1ced16", "trace_id": "de74f802d1e080066a9e9a141467e915", "span_id": "34e62201eade6a8e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.811, "client_addr": "10.244.0.1"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T04:00:03Z)

- Failed step: `browser driver 'logout' interaction failed (rc=2): WARN Retry attempt #0. Sleeping 494.096687ms before the next attempt
WARN Retry attempt #0. Sleeping 113.11157ms before the next attempt
WARN Retry attempt #1. Sleeping 202.576595ms before the next attempt
WARN Retry attempt #2. Sleeping 3.463378209s before the next attempt
WARN Retry attempt #1. Sleeping 1.013633578s before the next attempt
WARN Retry attempt #2. Sleeping 695.651466ms before the next attempt
error: Failed to fetch: `https://pypi.org/simple/cryptography/`
  Caused by: Could not connect, are you offline?
  Caused by: Request failed after 3 retries
  Caused by: error sending request for url (https://pypi.org/simple/cryptography/)
  Caused by: client error (Connect)
  Caused by: dns error: failed to lookup address information: nodename nor servname provided, or not known
  Ca`
- last API response (HTTP 200):
```json
{"tools":[{"name":"probe_write","title":null,"description":"Append a per-call nonce to the proof-local invocation ledger and return the nonce plus the ledger line count. Business-side-effect-free: the ledger is proof instrumentation for the ADR-014 four-eyes approval proof (the independent observer that makes 'zero execution' provable), not a business write.","inputSchema":{"properties":{"nonce":{"title":"Nonce","type":"string"}},"required":["nonce"],"title":"probe_writeArguments","type":"object"},"outputSchema":{"additionalProperties":true,"title":"probe_writeDictOutput","type":"object"},"icons":null,"annotations":null,"_meta":null,"execution":null}]}
```
- conversation.% chain rows (tail 10 — digest-only):
```
conversation.turn_completed|{"agent_run_id": "agent-run-6c55a84bda7c41b3b3ea85885439c2fd", "answer_bytes": 236, "answer_sha256": "9d2470bc585507a243380b8f3e92ecb5e8734251ee08df84ac3a338173095a6f", "completion_tokens": 44, "conversation_id": "d7a176b8-2814-4803-a9d4-90e0f30a04fd", "prompt_tokens": 970, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "seq": 1, "turn_id": "3611b09e-5d8f-475d-8b8e-7dd6172640b4", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
conversation.created|{"agent_id": "bank-analyst", "conversation_id": "d7a176b8-2814-4803-a9d4-90e0f30a04fd", "created_at": "2026-07-14T03:44:09.352544+00:00", "creator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- conversations operational records (tail 6 — no plaintext):
```
d7a176b8-2814-4803-a9d4-90e0f30a04fd | active | turns=1 | tokens=1014 | in_progress=false
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
agent.run.completed|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "answer_bytes": 236, "answer_sha256": "9d2470bc585507a243380b8f3e92ecb5e8734251ee08df84ac3a338173095a6f", "completion_tokens_total": 44, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prompt_tokens_total": 970, "run_id": "agent-run-6c55a84bda7c41b3b3ea85885439c2fd", "steps_used": 1}
agent.run.started|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "max_steps": 6, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prior_context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "prior_context_turns": 0, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "run_id": "agent-run-6c55a84bda7c41b3b3ea85885439c2fd", "token_budget": 60000, "wall_clock_s": 300.0}
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
agent-run-6c55a84bda7c41b3b3ea85885439c2fd-s0 | cognic-tier1-proof-m85c | openai/gpt-4o | external=true | resolved | ok
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m03:42:40 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m03:42:40 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#            'This product would be better if...'             #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:38800 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:41988 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53934 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47958 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53842 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51330 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:58526 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46812 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39218 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36428 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.29:50170 - "POST /chat/completions HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
{"approval_verified": false, "block_kind": null, "data_classes": ["operational_telemetry"], "purpose": "agent_run_notes", "record_id": "bf06d353-3088-4b35-835f-dbf33812f657", "redacted_value_digest": "e2a129e32081fd2c1afb58699d69f24c64a57cc62f3e2e8e9872308ecea5b7a0", "retention_until": null, "subject_ref": "human:https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "tier": "task", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"cae9281dbb83726f3d1dea08d32ab0e3ffae8617fd65b5847280d661b5ed68b3","refusal_reason":null,"registered_at":"2026-07-14T03:43:45.119975+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9dd4e58d5350d065b0116122e3a109a94b0e46a7d713c0fe6fd02f3c4db257bf","refusal_reason":null,"registered_at":"2026-07-14T03:43:45.388070+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T03:43:45.636338+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T03:43:45.892548+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T03:43:46.146321+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T03:43:46.392364+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T03:43:46.653239+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T03:43:46.906768+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T03:43:47.154397+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : aa9ab483c9162af3
    ID             : 40a9ffc9ec4afa5a
    Name           : GET /api/v1/conversations/{conversation_id}/transcript http send
    Kind           : Internal
    Start time     : 2026-07-14 03:44:15.003676879 +0000 UTC
    End time       : 2026-07-14 03:44:15.003704129 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #21
    Trace ID       : 6b740bac3f086289291a3e34a97d11f6
    Parent ID      : aa9ab483c9162af3
    ID             : 9642c7135d207d48
    Name           : GET /api/v1/conversations/{conversation_id}/transcript http send
    Kind           : Internal
    Start time     : 2026-07-14 03:44:15.003876046 +0000 UTC
    End time       : 2026-07-14 03:44:15.003885838 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #22
    Trace ID       : 6b740bac3f086289291a3e34a97d11f6
    Parent ID      : aa9ab483c9162af3
    ID             : f91a6d7979e907c8
    Name           : GET /api/v1/conversations/{conversation_id}/transcript http send
    Kind           : Internal
    Start time     : 2026-07-14 03:44:15.003923296 +0000 UTC
    End time       : 2026-07-14 03:44:15.003929296 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #23
    Trace ID       : 6b740bac3f086289291a3e34a97d11f6
    Parent ID      :
    ID             : aa9ab483c9162af3
    Name           : GET /api/v1/conversations/{conversation_id}/transcript
    Kind           : Server
    Start time     : 2026-07-14 03:44:14.999150046 +0000 UTC
    End time       : 2026-07-14 03:44:15.003945754 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/transcript)
     -> http.url: Str(https://rel-agentos:8443/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/transcript)
     -> http.method: Str(GET)
     -> http.server_name: Str(rel-agentos:8443)
     -> http.user_agent: Str(python-httpx/0.28.1)
     -> net.peer.ip: Str(10.244.0.30)
     -> net.peer.port: Int(45644)
     -> http.route: Str(/api/v1/conversations/{conversation_id}/transcript)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 03:43:44,232", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 03:43:47,729", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 03:43:48,300", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f27e1984ee6e4d3c90b6808cc6d5e910", "trace_id": "2991bb090dd43b39cc8abcaf9a13cc92", "span_id": "900fd3975b6ab9f8", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.981, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:43:48,603", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a5cd8b6b969f4b9e83afa0d0c72e8609", "trace_id": "15603aef33d1a6800fbabbaf46c6ff6c", "span_id": "b0f0472339ac16be"}
{"ts": "2026-07-14 03:43:48,615", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a5cd8b6b969f4b9e83afa0d0c72e8609", "trace_id": "15603aef33d1a6800fbabbaf46c6ff6c", "span_id": "b0f0472339ac16be"}
{"ts": "2026-07-14 03:43:48,625", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a5cd8b6b969f4b9e83afa0d0c72e8609", "trace_id": "15603aef33d1a6800fbabbaf46c6ff6c", "span_id": "b0f0472339ac16be"}
{"ts": "2026-07-14 03:43:48,625", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a5cd8b6b969f4b9e83afa0d0c72e8609", "trace_id": "15603aef33d1a6800fbabbaf46c6ff6c", "span_id": "b0f0472339ac16be", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 28.767, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:43:49,737", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-504816db3da94bc1bc0e4881b18e5778", "trace_id": "d69b8d8b3995110a293b3cc633cf05a2", "span_id": "3b98bbaba152216f", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.136, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 03:43:49,803", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 401 Unauthorized\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:49,808", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/.well-known/oauth-protected-resource/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:49,811", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://192.88.99.9:9000/.well-known/oauth-authorization-server \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:49,813", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://192.88.99.9:9000/token \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,031", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,031", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Received session ID: ca86780ea0a8467fbd305546b606c61c", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,032", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Negotiated protocol version: 2025-11-25", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,035", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 202 Accepted\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,035", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,037", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,039", "level": "INFO", "logger": "httpx", "message": "HTTP Request: DELETE http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,040", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "GET stream disconnected, reconnecting in 1000ms...", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea"}
{"ts": "2026-07-14 03:43:50,040", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-772be8b086e647d685cc91aa6fa2bd3c", "trace_id": "b5908fe05f6c6e89055a707811614839", "span_id": "b2ad6f7f1ae5d7ea", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 248.363, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 03:43:52,650", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-bd78e4b46a344764a597f9362e036933", "trace_id": "8c23c3fb88e0e97793c9742fe8a80de4", "span_id": "eaf59a95cf6e04b6", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:43:52,651", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bd78e4b46a344764a597f9362e036933", "trace_id": "8c23c3fb88e0e97793c9742fe8a80de4", "span_id": "eaf59a95cf6e04b6", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 5.884, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 03:43:53,298", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a4e0bc5b003c40709c21e47231514158", "trace_id": "e71b71e8728c54302c2850674246592a", "span_id": "802e5eee9f4db3d3", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.202, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:43:56,683", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-392e925300c64d8881371335c4853676", "trace_id": "7af4e46a216aa42146eb5e9987d218fe", "span_id": "aef6d1b05b5cfd33", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:43:56,683", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-392e925300c64d8881371335c4853676", "trace_id": "7af4e46a216aa42146eb5e9987d218fe", "span_id": "aef6d1b05b5cfd33", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.644, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 03:43:58,513", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-32d65c55d64d41e8a0bc8337f6448e19", "trace_id": "0a7ebce78ce9eabfbdc987b12ea1385d", "span_id": "c8985fece9ed4ddf", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:43:58,513", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-32d65c55d64d41e8a0bc8337f6448e19", "trace_id": "0a7ebce78ce9eabfbdc987b12ea1385d", "span_id": "c8985fece9ed4ddf", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.221, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 03:43:58,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f33da171ece84062bb15030d7ecb3f67", "trace_id": "5aa0d057cff87c926af970699ca947f9", "span_id": "f9bcdaed9e4f3bfa"}
{"ts": "2026-07-14 03:43:58,609", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f33da171ece84062bb15030d7ecb3f67", "trace_id": "5aa0d057cff87c926af970699ca947f9", "span_id": "f9bcdaed9e4f3bfa"}
{"ts": "2026-07-14 03:43:58,620", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f33da171ece84062bb15030d7ecb3f67", "trace_id": "5aa0d057cff87c926af970699ca947f9", "span_id": "f9bcdaed9e4f3bfa"}
{"ts": "2026-07-14 03:43:58,620", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f33da171ece84062bb15030d7ecb3f67", "trace_id": "5aa0d057cff87c926af970699ca947f9", "span_id": "f9bcdaed9e4f3bfa", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.632, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:44:07,454", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-0a1aa30b6b024ed0a4d336c7351fd088", "trace_id": "bd0de8167ce2301d206c3bcb71ba37dc", "span_id": "8ac35e1c7952c747", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:07,454", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0a1aa30b6b024ed0a4d336c7351fd088", "trace_id": "bd0de8167ce2301d206c3bcb71ba37dc", "span_id": "8ac35e1c7952c747", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.475, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:08,295", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a2062205955d43429660c40e81adc258", "trace_id": "52e1dbc0b4d323cec34238f82f2492f5", "span_id": "565bb56d0fd67902", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.131, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:44:08,425", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-286f0d4e1e7a4943aa8fd4205be9bc40", "trace_id": "1c15c79c83aa0266a869b1c5bc3721f5", "span_id": "f782087db1c55820", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:08,425", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-286f0d4e1e7a4943aa8fd4205be9bc40", "trace_id": "1c15c79c83aa0266a869b1c5bc3721f5", "span_id": "f782087db1c55820", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.521, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:08,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5a5b680f049745af8d4602d8d17c58af", "trace_id": "b5737dd985b6b8644f29c5f5246c0486", "span_id": "33a59a477171ffdc"}
{"ts": "2026-07-14 03:44:08,608", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5a5b680f049745af8d4602d8d17c58af", "trace_id": "b5737dd985b6b8644f29c5f5246c0486", "span_id": "33a59a477171ffdc"}
{"ts": "2026-07-14 03:44:08,618", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5a5b680f049745af8d4602d8d17c58af", "trace_id": "b5737dd985b6b8644f29c5f5246c0486", "span_id": "33a59a477171ffdc"}
{"ts": "2026-07-14 03:44:08,618", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5a5b680f049745af8d4602d8d17c58af", "trace_id": "b5737dd985b6b8644f29c5f5246c0486", "span_id": "33a59a477171ffdc", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.161, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 03:44:09,201", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-e5263c87911342c18d183bc68309e57e", "trace_id": "41a2e81b79230b9f8822455dd0048618", "span_id": "fd15bf87887a011f", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:09,201", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e5263c87911342c18d183bc68309e57e", "trace_id": "41a2e81b79230b9f8822455dd0048618", "span_id": "fd15bf87887a011f", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.245, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:09,357", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-feddf5aaffcb4f488253d83373bafebc", "trace_id": "02857beb4efe74da778d3ecc56d26570", "span_id": "77696d7c616b0202", "http_method": "POST", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 6.97, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:09,366", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-b492d0ec184d4eeabe1d69029a29846f", "trace_id": "5658624ca2a5366c6ccb964c95077c97", "span_id": "eac443f6cddc6a36", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:09,366", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b492d0ec184d4eeabe1d69029a29846f", "trace_id": "5658624ca2a5366c6ccb964c95077c97", "span_id": "eac443f6cddc6a36", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.141, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:09,373", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-2171d80649074927a08c412b600ccb13", "trace_id": "8b8cba14f022ac187d6be973280370ff", "span_id": "f64e0e5ecfff820b", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "d7a176b8-2814-4803-a9d4-90e0f30a04fd", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:09,373", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2171d80649074927a08c412b600ccb13", "trace_id": "8b8cba14f022ac187d6be973280370ff", "span_id": "f64e0e5ecfff820b", "http_method": "GET", "http_path": "/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 5.16, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:13,881", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://litellm:4000/chat/completions \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1584a78cc2614220827c2c948fc44738", "trace_id": "e091c609a16b30c5706df678e2035ec8", "span_id": "ef0a6f14b1254919"}
{"ts": "2026-07-14 03:44:13,901", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1584a78cc2614220827c2c948fc44738", "trace_id": "e091c609a16b30c5706df678e2035ec8", "span_id": "ef0a6f14b1254919", "http_method": "POST", "http_path": "/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/turns", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 4459.945, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:13,911", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-9bbc6904670d4354bc8d9602a81df5f5", "trace_id": "b8faa3aab2a6ecf9282e17a4cee7c240", "span_id": "92d62870c62bd8e7", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:13,912", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9bbc6904670d4354bc8d9602a81df5f5", "trace_id": "b8faa3aab2a6ecf9282e17a4cee7c240", "span_id": "92d62870c62bd8e7", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.075, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:13,917", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-d7e1420b2aed4213a837f9ec6cf7e48c", "trace_id": "cc704f31e24f8a6b4ae9e502d04b8223", "span_id": "2c3133c10752d57a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "d7a176b8-2814-4803-a9d4-90e0f30a04fd", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:13,917", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d7e1420b2aed4213a837f9ec6cf7e48c", "trace_id": "cc704f31e24f8a6b4ae9e502d04b8223", "span_id": "2c3133c10752d57a", "http_method": "GET", "http_path": "/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 3.454, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:14,885", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-6938df6c82cc48edb6724c173e81f5a2", "trace_id": "6edab70b7e22d32ff3ba45aec3954a23", "span_id": "6896ff35d078640a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:14,885", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-6938df6c82cc48edb6724c173e81f5a2", "trace_id": "6edab70b7e22d32ff3ba45aec3954a23", "span_id": "6896ff35d078640a", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.975, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:14,892", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-7c19731f1482442a95f08790df74a9af", "trace_id": "99c889507ded279a3582185c6fd57a20", "span_id": "e5812986ca681c73", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "d7a176b8-2814-4803-a9d4-90e0f30a04fd", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:14,893", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7c19731f1482442a95f08790df74a9af", "trace_id": "99c889507ded279a3582185c6fd57a20", "span_id": "e5812986ca681c73", "http_method": "GET", "http_path": "/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 4.472, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 03:44:15,003", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-021d1ec5f03f48f5be8c6078974399e3", "trace_id": "6b740bac3f086289291a3e34a97d11f6", "span_id": "aa9ab483c9162af3", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "d7a176b8-2814-4803-a9d4-90e0f30a04fd", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 03:44:15,003", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-021d1ec5f03f48f5be8c6078974399e3", "trace_id": "6b740bac3f086289291a3e34a97d11f6", "span_id": "aa9ab483c9162af3", "http_method": "GET", "http_path": "/api/v1/conversations/d7a176b8-2814-4803-a9d4-90e0f30a04fd/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 4.036, "client_addr": "10.244.0.30"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T07:34:21Z)

- Failed step: `Keycloak admin token could not be obtained (admin-cli password grant on the master realm)`
- last API response (HTTP 200):
```json
{"tools":[{"name":"probe_write","title":null,"description":"Append a per-call nonce to the proof-local invocation ledger and return the nonce plus the ledger line count. Business-side-effect-free: the ledger is proof instrumentation for the ADR-014 four-eyes approval proof (the independent observer that makes 'zero execution' provable), not a business write.","inputSchema":{"properties":{"nonce":{"title":"Nonce","type":"string"}},"required":["nonce"],"title":"probe_writeArguments","type":"object"},"outputSchema":{"additionalProperties":true,"title":"probe_writeDictOutput","type":"object"},"icons":null,"annotations":null,"_meta":null,"execution":null}]}
```
- conversation.% chain rows (tail 10 — digest-only):
```
conversation.turn_completed|{"agent_run_id": "agent-run-3029757b7e4e4307864f7951c3f525bc", "answer_bytes": 174, "answer_sha256": "fa2c0c4b7fed8949e882192a92fd6409f6e0b68312bce98fb68cfc72fb47f4c7", "completion_tokens": 38, "conversation_id": "c7fa662e-53d3-4de6-826d-9485a45dbaea", "prompt_tokens": 970, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "seq": 1, "turn_id": "151deb41-97bd-4c7b-8bf3-e9e22e641f71", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
conversation.created|{"agent_id": "bank-analyst", "conversation_id": "c7fa662e-53d3-4de6-826d-9485a45dbaea", "created_at": "2026-07-14T07:33:53.991747+00:00", "creator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- conversations operational records (tail 6 — no plaintext):
```
c7fa662e-53d3-4de6-826d-9485a45dbaea | active | turns=1 | tokens=1008 | in_progress=false
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
agent.run.completed|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "answer_bytes": 174, "answer_sha256": "fa2c0c4b7fed8949e882192a92fd6409f6e0b68312bce98fb68cfc72fb47f4c7", "completion_tokens_total": 38, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prompt_tokens_total": 970, "run_id": "agent-run-3029757b7e4e4307864f7951c3f525bc", "steps_used": 1}
agent.run.started|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "max_steps": 6, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prior_context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "prior_context_turns": 0, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "run_id": "agent-run-3029757b7e4e4307864f7951c3f525bc", "token_budget": 60000, "wall_clock_s": 300.0}
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
agent-run-3029757b7e4e4307864f7951c3f525bc-s0 | cognic-tier1-proof-m85c | openai/gpt-4o | external=true | resolved | ok
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
[92m07:32:12 - LiteLLM:WARNING[0m: get_model_cost_map.py:290 - LiteLLM: Failed to fetch remote model cost map from https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json: _ssl.c:1015: The handshake operation timed out. Falling back to local backup.
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m07:32:20 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m07:32:20 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#         'The worst thing about this product is...'          #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:39696 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:43272 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:52918 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:44558 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54722 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:48422 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:48004 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:38250 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:45162 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33656 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.29:58360 - "POST /chat/completions HTTP/1.1" 200 OK
INFO:     10.244.0.1:47912 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46402 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
{"approval_verified": false, "block_kind": null, "data_classes": ["operational_telemetry"], "purpose": "agent_run_notes", "record_id": "865af8c7-b965-4d52-9ff0-99504583be69", "redacted_value_digest": "e2a129e32081fd2c1afb58699d69f24c64a57cc62f3e2e8e9872308ecea5b7a0", "retention_until": null, "subject_ref": "human:https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "tier": "task", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"2514ebfbae7386fa2958e9239837049e41ab97c4c1acea2b1c687130ef910c73","refusal_reason":null,"registered_at":"2026-07-14T07:33:25.161141+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"73c4c310b27f4917e1c8069e44f50539da2ac82503c5e15e6c611b72cba917b1","refusal_reason":null,"registered_at":"2026-07-14T07:33:25.363346+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T07:33:25.563644+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T07:33:25.765817+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T07:33:26.053918+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T07:33:26.258010+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T07:33:26.452125+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T07:33:26.655246+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T07:33:26.851235+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : f7b5e420989684b5
    ID             : 2bcab7b24199c843
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 07:34:09.906721595 +0000 UTC
    End time       : 2026-07-14 07:34:09.906747053 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #1
    Trace ID       : e9f284a1a3244df8bec40c065fc3b7d4
    Parent ID      : f7b5e420989684b5
    ID             : 8b96e59b2a799b15
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 07:34:09.906877928 +0000 UTC
    End time       : 2026-07-14 07:34:09.906884303 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #2
    Trace ID       : e9f284a1a3244df8bec40c065fc3b7d4
    Parent ID      : f7b5e420989684b5
    ID             : a1817e3d088661ac
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 07:34:09.906911678 +0000 UTC
    End time       : 2026-07-14 07:34:09.90691697 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #3
    Trace ID       : e9f284a1a3244df8bec40c065fc3b7d4
    Parent ID      :
    ID             : f7b5e420989684b5
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-14 07:34:09.884655803 +0000 UTC
    End time       : 2026-07-14 07:34:09.906971803 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.29:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.29:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(41488)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 07:33:24,437", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 07:33:27,314", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 07:33:29,419", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3aefce132dbc47808637889ec068c899", "trace_id": "1cb25e94464131c9072120667b7db4ab", "span_id": "fa5eb380b489e47b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.814, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:33:29,891", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0e5ff1373d0846c0944663a6ccbf4004", "trace_id": "dcb428d8d0265cc3c1a8abb029b0258c", "span_id": "4fa450c503dd1f84"}
{"ts": "2026-07-14 07:33:29,904", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0e5ff1373d0846c0944663a6ccbf4004", "trace_id": "dcb428d8d0265cc3c1a8abb029b0258c", "span_id": "4fa450c503dd1f84"}
{"ts": "2026-07-14 07:33:29,915", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0e5ff1373d0846c0944663a6ccbf4004", "trace_id": "dcb428d8d0265cc3c1a8abb029b0258c", "span_id": "4fa450c503dd1f84"}
{"ts": "2026-07-14 07:33:29,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0e5ff1373d0846c0944663a6ccbf4004", "trace_id": "dcb428d8d0265cc3c1a8abb029b0258c", "span_id": "4fa450c503dd1f84", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 31.121, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:33:30,997", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-95311c143d7f484e85b52fc25e3aa062", "trace_id": "642b69de877641b1cbc265928818cc44", "span_id": "3571c0d63d812bc5", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.125, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 07:33:31,056", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 401 Unauthorized\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,060", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/.well-known/oauth-protected-resource/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,062", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://192.88.99.9:9000/.well-known/oauth-authorization-server \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,064", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://192.88.99.9:9000/token \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,236", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,236", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Received session ID: 01a2b2a67c554f278ae66cb3f80f5678", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,236", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Negotiated protocol version: 2025-11-25", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,239", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 202 Accepted\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,239", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,241", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,242", "level": "INFO", "logger": "httpx", "message": "HTTP Request: DELETE http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,243", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "GET stream disconnected, reconnecting in 1000ms...", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06"}
{"ts": "2026-07-14 07:33:31,243", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fc608ff0e3084c038d20cc833ee51675", "trace_id": "58bf45053cd8e45177aed6f384381daa", "span_id": "467ed8e9bc514d06", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 198.541, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 07:33:34,414", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-728aa865df9747bcadef17a3838ff538", "trace_id": "fe9908942a181109536845b589d8cf90", "span_id": "bc757f52755f0d24", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.247, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:33:38,274", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-baca6174de0e4905841e5e9b39c358b9", "trace_id": "296c9d8eba2c54e7eacd01fef2e94101", "span_id": "a921e9293bc3b76e", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:38,274", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-baca6174de0e4905841e5e9b39c358b9", "trace_id": "296c9d8eba2c54e7eacd01fef2e94101", "span_id": "a921e9293bc3b76e", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 5.307, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 07:33:39,884", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc27e03ccf22451396e4981a3f4e23f8", "trace_id": "41b22070d6c022925c57b32351e9d300", "span_id": "6a9190ac10d52b94"}
{"ts": "2026-07-14 07:33:39,897", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc27e03ccf22451396e4981a3f4e23f8", "trace_id": "41b22070d6c022925c57b32351e9d300", "span_id": "6a9190ac10d52b94"}
{"ts": "2026-07-14 07:33:39,905", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fc27e03ccf22451396e4981a3f4e23f8", "trace_id": "41b22070d6c022925c57b32351e9d300", "span_id": "6a9190ac10d52b94"}
{"ts": "2026-07-14 07:33:39,905", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fc27e03ccf22451396e4981a3f4e23f8", "trace_id": "41b22070d6c022925c57b32351e9d300", "span_id": "6a9190ac10d52b94", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.348, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:33:41,725", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-f10bbbc247d54689aadadb12d930d1b5", "trace_id": "3d799ac93735044338e23a2e0e6071c8", "span_id": "aae8863c2df66bf7", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:41,725", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f10bbbc247d54689aadadb12d930d1b5", "trace_id": "3d799ac93735044338e23a2e0e6071c8", "span_id": "aae8863c2df66bf7", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.335, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 07:33:43,427", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-1da5f8a5a9fb444999e9887da33d4d55", "trace_id": "7dff58b9f7f2e2e6bf46977434a4c7c9", "span_id": "bbcd402b3fba8888", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:43,427", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1da5f8a5a9fb444999e9887da33d4d55", "trace_id": "7dff58b9f7f2e2e6bf46977434a4c7c9", "span_id": "bbcd402b3fba8888", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.144, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 07:33:49,413", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e2e53f6c4a5449d7b07931cafc9a9649", "trace_id": "2d4c7ef7cce20b4cd326cddb7a719508", "span_id": "629b26ec2e4fdfe0", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.293, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:33:49,889", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-edd2f551bd924ec69ac1ac62bbbaeb25", "trace_id": "c753ee5c7ee091fb4970d2ee57c77ade", "span_id": "1ce3b6e100ed4432"}
{"ts": "2026-07-14 07:33:49,898", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-edd2f551bd924ec69ac1ac62bbbaeb25", "trace_id": "c753ee5c7ee091fb4970d2ee57c77ade", "span_id": "1ce3b6e100ed4432"}
{"ts": "2026-07-14 07:33:49,906", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-edd2f551bd924ec69ac1ac62bbbaeb25", "trace_id": "c753ee5c7ee091fb4970d2ee57c77ade", "span_id": "1ce3b6e100ed4432"}
{"ts": "2026-07-14 07:33:49,906", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-edd2f551bd924ec69ac1ac62bbbaeb25", "trace_id": "c753ee5c7ee091fb4970d2ee57c77ade", "span_id": "1ce3b6e100ed4432", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.19, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:33:52,610", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ef3cb1b6d9e146899fa1132f1321b8a2", "trace_id": "e91554973fe48b011ebf6be02427a16b", "span_id": "9f7927a86c067f04", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:52,611", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ef3cb1b6d9e146899fa1132f1321b8a2", "trace_id": "e91554973fe48b011ebf6be02427a16b", "span_id": "9f7927a86c067f04", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.075, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:33:53,223", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-4ddd22a356b342b488e2f5919b82b1af", "trace_id": "25d2d08a1e0b17826ea2e6b769c79ee4", "span_id": "091c0ccb11e71895", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:53,223", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4ddd22a356b342b488e2f5919b82b1af", "trace_id": "25d2d08a1e0b17826ea2e6b769c79ee4", "span_id": "091c0ccb11e71895", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.35, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:33:53,856", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ba216ce4e0404b26a1d3e1a647f690be", "trace_id": "ac6463db24e5d637fe4b163998b6fad8", "span_id": "b457c9252fb7df79", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:53,856", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ba216ce4e0404b26a1d3e1a647f690be", "trace_id": "ac6463db24e5d637fe4b163998b6fad8", "span_id": "b457c9252fb7df79", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.335, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:33:53,997", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-35c00cd240f9404d9c4e8c7298dbae75", "trace_id": "379d72c8de3a70ce18dc2e95d732d25a", "span_id": "40cdb21152633a90", "http_method": "POST", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 7.641, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:33:54,005", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-35fc888477db477db6f00a5bfcceed0d", "trace_id": "0fbadaf5d25353709c853d13ba42b5b8", "span_id": "90df4898890f3914", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:54,005", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-35fc888477db477db6f00a5bfcceed0d", "trace_id": "0fbadaf5d25353709c853d13ba42b5b8", "span_id": "90df4898890f3914", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.8, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:33:54,009", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-ecf4674f938e443bb2c39baa2caf6edd", "trace_id": "d6de5882b6db5d6de8027bea276c8d09", "span_id": "86b81e13d9983193", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "c7fa662e-53d3-4de6-826d-9485a45dbaea", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:33:54,009", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ecf4674f938e443bb2c39baa2caf6edd", "trace_id": "d6de5882b6db5d6de8027bea276c8d09", "span_id": "86b81e13d9983193", "http_method": "GET", "http_path": "/api/v1/conversations/c7fa662e-53d3-4de6-826d-9485a45dbaea/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.711, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:33:59,889", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f11cccb7a24142eb84bb6d6ff1ed8d18", "trace_id": "2832bf0d344bbace93b4e39a98b72a72", "span_id": "71c298ba223d96b7"}
{"ts": "2026-07-14 07:33:59,898", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f11cccb7a24142eb84bb6d6ff1ed8d18", "trace_id": "2832bf0d344bbace93b4e39a98b72a72", "span_id": "71c298ba223d96b7"}
{"ts": "2026-07-14 07:33:59,906", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f11cccb7a24142eb84bb6d6ff1ed8d18", "trace_id": "2832bf0d344bbace93b4e39a98b72a72", "span_id": "71c298ba223d96b7"}
{"ts": "2026-07-14 07:33:59,906", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f11cccb7a24142eb84bb6d6ff1ed8d18", "trace_id": "2832bf0d344bbace93b4e39a98b72a72", "span_id": "71c298ba223d96b7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.822, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:34:00,985", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://litellm:4000/chat/completions \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e1742669e6054863979145d544e43074", "trace_id": "62efb744f0e08f988309e58b40a7cfec", "span_id": "9a0bcf1b82cfd9bf"}
{"ts": "2026-07-14 07:34:01,004", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e1742669e6054863979145d544e43074", "trace_id": "62efb744f0e08f988309e58b40a7cfec", "span_id": "9a0bcf1b82cfd9bf", "http_method": "POST", "http_path": "/api/v1/conversations/c7fa662e-53d3-4de6-826d-9485a45dbaea/turns", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 6937.677, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:01,013", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-50415aa1447a4caf8ab3f79ba3c9cc2b", "trace_id": "d5f93860231efc562b4ecede2e1f5b22", "span_id": "a0d2dab0ba5405e2", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:01,014", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-50415aa1447a4caf8ab3f79ba3c9cc2b", "trace_id": "d5f93860231efc562b4ecede2e1f5b22", "span_id": "a0d2dab0ba5405e2", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.693, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:01,018", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-282f9be61aa345e385cccd71aae3a369", "trace_id": "454137a23202350408db541dc0d56a33", "span_id": "6ee1001bcdf1a9c5", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "c7fa662e-53d3-4de6-826d-9485a45dbaea", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:01,018", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-282f9be61aa345e385cccd71aae3a369", "trace_id": "454137a23202350408db541dc0d56a33", "span_id": "6ee1001bcdf1a9c5", "http_method": "GET", "http_path": "/api/v1/conversations/c7fa662e-53d3-4de6-826d-9485a45dbaea/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 3.217, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:01,558", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-57119f81131e495a9c6e8e2ac2601afd", "trace_id": "231d652fe3f0d924e83135cba8c9f48c", "span_id": "91866ed0989329a4", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:01,558", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-57119f81131e495a9c6e8e2ac2601afd", "trace_id": "231d652fe3f0d924e83135cba8c9f48c", "span_id": "91866ed0989329a4", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.974, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:01,562", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-f0121a583d1047c185a5a5e66d7c25d2", "trace_id": "bfb227f70f5fbbe23a35329f3eb2126a", "span_id": "e5a1089e229caa27", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "c7fa662e-53d3-4de6-826d-9485a45dbaea", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:01,562", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f0121a583d1047c185a5a5e66d7c25d2", "trace_id": "bfb227f70f5fbbe23a35329f3eb2126a", "span_id": "e5a1089e229caa27", "http_method": "GET", "http_path": "/api/v1/conversations/c7fa662e-53d3-4de6-826d-9485a45dbaea/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.544, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:01,654", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-57805019113b462ca0979e3f65d55eab", "trace_id": "500a7078e4854587d20fe4d12e3bd6af", "span_id": "05c9a1b6d40b7b5f", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "c7fa662e-53d3-4de6-826d-9485a45dbaea", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:01,655", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-57805019113b462ca0979e3f65d55eab", "trace_id": "500a7078e4854587d20fe4d12e3bd6af", "span_id": "05c9a1b6d40b7b5f", "http_method": "GET", "http_path": "/api/v1/conversations/c7fa662e-53d3-4de6-826d-9485a45dbaea/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 3.06, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:02,200", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ddf910e1c0014d8486e19b90983f672b", "trace_id": "a43e122980ff0e0ee1ac115ec28e43b5", "span_id": "9c85609dc8a9fb0c", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:02,200", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ddf910e1c0014d8486e19b90983f672b", "trace_id": "a43e122980ff0e0ee1ac115ec28e43b5", "span_id": "9c85609dc8a9fb0c", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.361, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:04,428", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-933dae19f409443293e0a7a31d28adb6", "trace_id": "6525c6d7f8545f44ba3d83119f1ae55a", "span_id": "0351ead0bf7f9faf", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.121, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:34:07,441", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d7be63c2b0af47109825842ece18bffc", "trace_id": "ae29e3120eb53ca4f26e436bfabb9c58", "span_id": "3e48a7501a3fb994", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:07,441", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d7be63c2b0af47109825842ece18bffc", "trace_id": "ae29e3120eb53ca4f26e436bfabb9c58", "span_id": "3e48a7501a3fb994", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.192, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:07,633", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-2721fba265ed48289cd05befb5e62d96", "trace_id": "3f239c1cebc7e81b16199244d632382f", "span_id": "b4d0aa81863dafb0", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 07:34:07,633", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2721fba265ed48289cd05befb5e62d96", "trace_id": "3f239c1cebc7e81b16199244d632382f", "span_id": "b4d0aa81863dafb0", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.108, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 07:34:09,889", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3b3e21aa4b0a4d1a8ec40f86d5938545", "trace_id": "e9f284a1a3244df8bec40c065fc3b7d4", "span_id": "f7b5e420989684b5"}
{"ts": "2026-07-14 07:34:09,898", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3b3e21aa4b0a4d1a8ec40f86d5938545", "trace_id": "e9f284a1a3244df8bec40c065fc3b7d4", "span_id": "f7b5e420989684b5"}
{"ts": "2026-07-14 07:34:09,906", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3b3e21aa4b0a4d1a8ec40f86d5938545", "trace_id": "e9f284a1a3244df8bec40c065fc3b7d4", "span_id": "f7b5e420989684b5"}
{"ts": "2026-07-14 07:34:09,906", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3b3e21aa4b0a4d1a8ec40f86d5938545", "trace_id": "e9f284a1a3244df8bec40c065fc3b7d4", "span_id": "f7b5e420989684b5", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.531, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:34:19,416", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ee1d064ecce945ee9fdae72e5a2ce8a3", "trace_id": "65b2f56dd113cd79b4d6484af21494dc", "span_id": "250406fc3ad8d126", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.347, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 07:34:19,892", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-012a973ffd76495cb67c51e52244ee4d", "trace_id": "32a19e8a1d1601ea513878bee7e80d18", "span_id": "976bde02bf9d2e8a"}
{"ts": "2026-07-14 07:34:19,900", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-012a973ffd76495cb67c51e52244ee4d", "trace_id": "32a19e8a1d1601ea513878bee7e80d18", "span_id": "976bde02bf9d2e8a"}
{"ts": "2026-07-14 07:34:19,909", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-012a973ffd76495cb67c51e52244ee4d", "trace_id": "32a19e8a1d1601ea513878bee7e80d18", "span_id": "976bde02bf9d2e8a"}
{"ts": "2026-07-14 07:34:19,909", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-012a973ffd76495cb67c51e52244ee4d", "trace_id": "32a19e8a1d1601ea513878bee7e80d18", "span_id": "976bde02bf9d2e8a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.72, "client_addr": "10.244.0.1"}
```

## Proof M8.5-C BFF readiness diagnostics (2026-07-14T09:07:24Z)

- Failed step: `per-pod port-forward to pod/cognic-proof-harness-66ddb8cfb8-j4kkd did not become reachable`
- BFF deployment + pods:
```
NAME                                   READY   UP-TO-DATE   AVAILABLE   AGE     CONTAINERS   IMAGES                     SELECTOR
deployment.apps/cognic-proof-harness   2/2     2            2           2m26s   harness      cognic-harness:proofm85c   app=cognic-proof-harness

NAME                                        READY   STATUS    RESTARTS   AGE   IP            NODE                             NOMINATED NODE   READINESS GATES
pod/cognic-proof-harness-77c69f5dc5-844cv   1/1     Running   0          43s   10.244.0.32   cognic-proofm85c-control-plane   <none>           <none>
pod/cognic-proof-harness-77c69f5dc5-f24x7   1/1     Running   0          37s   10.244.0.33   cognic-proofm85c-control-plane   <none>           <none>
```
- BFF pod describe/events (tail 180; access logs deliberately excluded):
```
Name:             cognic-proof-harness-77c69f5dc5-844cv
Namespace:        cognic-proofm85c
Priority:         0
Service Account:  default
Node:             cognic-proofm85c-control-plane/172.27.0.2
Start Time:       Tue, 14 Jul 2026 14:06:41 +0500
Labels:           app=cognic-proof-harness
                  pod-template-hash=77c69f5dc5
Annotations:      <none>
Status:           Running
SeccompProfile:   RuntimeDefault
IP:               10.244.0.32
IPs:
  IP:           10.244.0.32
Controlled By:  ReplicaSet/cognic-proof-harness-77c69f5dc5
Containers:
  harness:
    Container ID:   containerd://88b6e783244d3ac633b1f5425db4fe510a5bd384a7a13c72824f169e117e72ba
    Image:          cognic-harness:proofm85c
    Image ID:       docker.io/library/import-2026-07-14@sha256:089af7ae777c063ccb87a366b4ea4ad5400cf454aefe84ec1ef0801b457cb042
    Port:           8443/TCP
    Host Port:      0/TCP
    State:          Running
      Started:      Tue, 14 Jul 2026 14:06:42 +0500
    Ready:          True
    Restart Count:  0
    Readiness:      http-get https://:8443/signin delay=5s timeout=1s period=5s #success=1 #failure=30
    Environment:
      COGNIC_HARNESS_ENV:                     prod
      COGNIC_HARNESS_HOST:                    0.0.0.0
      COGNIC_HARNESS_PORT:                    8443
      COGNIC_HARNESS_AGENTOS_BASE_URL:        https://rel-agentos:8443
      COGNIC_HARNESS_AGENTOS_CA_BUNDLE:       /etc/proof-ca/proof-ca.pem
      COGNIC_HARNESS_OIDC_ISSUER:             https://cognic-proof-keycloak:8443/realms/proof-m85c
      COGNIC_HARNESS_OIDC_CLIENT_ID:          cognic-harness
      COGNIC_HARNESS_OIDC_REDIRECT_URI:       https://127.0.0.1:8444/auth/callback
      COGNIC_HARNESS_OIDC_TENANT_CLAIM:       tenant_id
      COGNIC_HARNESS_OIDC_CA_BUNDLE:          /etc/proof-ca/proof-ca.pem
      COGNIC_HARNESS_SESSION_BACKEND:         redis
      COGNIC_HARNESS_REDIS_CA_BUNDLE:         /etc/proof-ca/proof-ca.pem
      COGNIC_HARNESS_SESSION_IDLE_TTL_S:      60
      COGNIC_HARNESS_SESSION_ABSOLUTE_TTL_S:  150
      COGNIC_HARNESS_OIDC_CLIENT_SECRET:      <set to the key 'oidc-client-secret' in secret 'proof-m85c-harness-secrets'>   Optional: false
      COGNIC_HARNESS_SESSION_HMAC_SECRET:     <set to the key 'session-hmac-secret' in secret 'proof-m85c-harness-secrets'>  Optional: false
      COGNIC_HARNESS_REDIS_URL:               <set to the key 'redis-url' in secret 'proof-m85c-harness-secrets'>            Optional: false
    Mounts:
      /etc/harness-tls from harness-tls (ro)
      /etc/proof-ca from proof-ca (ro)
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-vn78b (ro)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True
  Initialized                 True
  Ready                       True
  ContainersReady             True
  PodScheduled                True
Volumes:
  harness-tls:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-harness-tls
    Optional:    false
  proof-ca:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-ca
    Optional:    false
  kube-api-access-vn78b:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    ConfigMapOptional:       <nil>
    DownwardAPI:             true
QoS Class:                   BestEffort
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type    Reason     Age   From               Message
  ----    ------     ----  ----               -------
  Normal  Scheduled  43s   default-scheduler  Successfully assigned cognic-proofm85c/cognic-proof-harness-77c69f5dc5-844cv to cognic-proofm85c-control-plane
  Normal  Pulled     42s   kubelet            Container image "cognic-harness:proofm85c" already present on machine and can be accessed by the pod
  Normal  Created    42s   kubelet            Container created
  Normal  Started    42s   kubelet            Container started


Name:             cognic-proof-harness-77c69f5dc5-f24x7
Namespace:        cognic-proofm85c
Priority:         0
Service Account:  default
Node:             cognic-proofm85c-control-plane/172.27.0.2
Start Time:       Tue, 14 Jul 2026 14:06:47 +0500
Labels:           app=cognic-proof-harness
                  pod-template-hash=77c69f5dc5
Annotations:      <none>
Status:           Running
SeccompProfile:   RuntimeDefault
IP:               10.244.0.33
IPs:
  IP:           10.244.0.33
Controlled By:  ReplicaSet/cognic-proof-harness-77c69f5dc5
Containers:
  harness:
    Container ID:   containerd://1b6fe41b9993de40d8550cea487b7a75ac146d6b374c809e1d30a380c450c4c1
    Image:          cognic-harness:proofm85c
    Image ID:       docker.io/library/import-2026-07-14@sha256:089af7ae777c063ccb87a366b4ea4ad5400cf454aefe84ec1ef0801b457cb042
    Port:           8443/TCP
    Host Port:      0/TCP
    State:          Running
      Started:      Tue, 14 Jul 2026 14:06:48 +0500
    Ready:          True
    Restart Count:  0
    Readiness:      http-get https://:8443/signin delay=5s timeout=1s period=5s #success=1 #failure=30
    Environment:
      COGNIC_HARNESS_ENV:                     prod
      COGNIC_HARNESS_HOST:                    0.0.0.0
      COGNIC_HARNESS_PORT:                    8443
      COGNIC_HARNESS_AGENTOS_BASE_URL:        https://rel-agentos:8443
      COGNIC_HARNESS_AGENTOS_CA_BUNDLE:       /etc/proof-ca/proof-ca.pem
      COGNIC_HARNESS_OIDC_ISSUER:             https://cognic-proof-keycloak:8443/realms/proof-m85c
      COGNIC_HARNESS_OIDC_CLIENT_ID:          cognic-harness
      COGNIC_HARNESS_OIDC_REDIRECT_URI:       https://127.0.0.1:8444/auth/callback
      COGNIC_HARNESS_OIDC_TENANT_CLAIM:       tenant_id
      COGNIC_HARNESS_OIDC_CA_BUNDLE:          /etc/proof-ca/proof-ca.pem
      COGNIC_HARNESS_SESSION_BACKEND:         redis
      COGNIC_HARNESS_REDIS_CA_BUNDLE:         /etc/proof-ca/proof-ca.pem
      COGNIC_HARNESS_SESSION_IDLE_TTL_S:      60
      COGNIC_HARNESS_SESSION_ABSOLUTE_TTL_S:  150
      COGNIC_HARNESS_OIDC_CLIENT_SECRET:      <set to the key 'oidc-client-secret' in secret 'proof-m85c-harness-secrets'>   Optional: false
      COGNIC_HARNESS_SESSION_HMAC_SECRET:     <set to the key 'session-hmac-secret' in secret 'proof-m85c-harness-secrets'>  Optional: false
      COGNIC_HARNESS_REDIS_URL:               <set to the key 'redis-url' in secret 'proof-m85c-harness-secrets'>            Optional: false
    Mounts:
      /etc/harness-tls from harness-tls (ro)
      /etc/proof-ca from proof-ca (ro)
      /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-tmfhw (ro)
Conditions:
  Type                        Status
  PodReadyToStartContainers   True
  Initialized                 True
  Ready                       True
  ContainersReady             True
  PodScheduled                True
Volumes:
  harness-tls:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-harness-tls
    Optional:    false
  proof-ca:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  proof-m85c-ca
    Optional:    false
  kube-api-access-tmfhw:
    Type:                    Projected (a volume that contains injected data from multiple sources)
    TokenExpirationSeconds:  3607
    ConfigMapName:           kube-root-ca.crt
    ConfigMapOptional:       <nil>
    DownwardAPI:             true
QoS Class:                   BestEffort
Node-Selectors:              <none>
Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                             node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:
  Type    Reason     Age   From               Message
  ----    ------     ----  ----               -------
  Normal  Scheduled  37s   default-scheduler  Successfully assigned cognic-proofm85c/cognic-proof-harness-77c69f5dc5-f24x7 to cognic-proofm85c-control-plane
  Normal  Pulled     36s   kubelet            Container image "cognic-harness:proofm85c" already present on machine and can be accessed by the pod
  Normal  Created    36s   kubelet            Container created
  Normal  Started    36s   kubelet            Container started
```

## Proof M8.5 slice — FAILURE (2026-07-14T09:07:25Z)

- Failed step: `per-pod port-forward to pod/cognic-proof-harness-66ddb8cfb8-j4kkd did not become reachable`
- last API response (HTTP 200):
```json
{"tools":[{"name":"probe_write","title":null,"description":"Append a per-call nonce to the proof-local invocation ledger and return the nonce plus the ledger line count. Business-side-effect-free: the ledger is proof instrumentation for the ADR-014 four-eyes approval proof (the independent observer that makes 'zero execution' provable), not a business write.","inputSchema":{"properties":{"nonce":{"title":"Nonce","type":"string"}},"required":["nonce"],"title":"probe_writeArguments","type":"object"},"outputSchema":{"additionalProperties":true,"title":"probe_writeDictOutput","type":"object"},"icons":null,"annotations":null,"_meta":null,"execution":null}]}
```
- conversation.% chain rows (tail 10 — digest-only):
```
conversation.turn_completed|{"agent_run_id": "agent-run-b4860cc8ec704d4b8bd048486fd29a17", "answer_bytes": 181, "answer_sha256": "c819dfb4b8764de371a9e8382f522e60ced1f52075aa791e0906d82c1e622f13", "completion_tokens": 38, "conversation_id": "b5006e1d-242d-43f9-90fd-f66ce3c3a420", "prompt_tokens": 970, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "seq": 1, "turn_id": "6e71212d-c33e-4cd3-a804-698ff2491bc8", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
conversation.created|{"agent_id": "bank-analyst", "conversation_id": "b5006e1d-242d-43f9-90fd-f66ce3c3a420", "created_at": "2026-07-14T09:05:52.675385+00:00", "creator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- conversations operational records (tail 6 — no plaintext):
```
b5006e1d-242d-43f9-90fd-f66ce3c3a420 | active | turns=1 | tokens=1008 | in_progress=false
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
agent.run.completed|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "answer_bytes": 181, "answer_sha256": "c819dfb4b8764de371a9e8382f522e60ced1f52075aa791e0906d82c1e622f13", "completion_tokens_total": 38, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prompt_tokens_total": 970, "run_id": "agent-run-b4860cc8ec704d4b8bd048486fd29a17", "steps_used": 1}
agent.run.started|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "max_steps": 6, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prior_context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "prior_context_turns": 0, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "run_id": "agent-run-b4860cc8ec704d4b8bd048486fd29a17", "token_budget": 60000, "wall_clock_s": 300.0}
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
agent-run-b4860cc8ec704d4b8bd048486fd29a17-s0 | cognic-tier1-proof-m85c | openai/gpt-4o | external=true | resolved | ok
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m09:04:29 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m09:04:29 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#            'This product would be better if...'             #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:35624 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51358 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35004 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:40454 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47596 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54930 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:50904 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:37612 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39956 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.29:35512 - "POST /chat/completions HTTP/1.1" 200 OK
INFO:     10.244.0.1:52212 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33846 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:59056 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:58376 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46128 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57298 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35712 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46228 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:42328 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
{"approval_verified": false, "block_kind": null, "data_classes": ["operational_telemetry"], "purpose": "agent_run_notes", "record_id": "b0db4b15-74ab-4cf7-8433-8dce7b5996b9", "redacted_value_digest": "e2a129e32081fd2c1afb58699d69f24c64a57cc62f3e2e8e9872308ecea5b7a0", "retention_until": null, "subject_ref": "human:https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "tier": "task", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"391874f10386d29bfabc809a048993784d183c9ef5c01dc71ddaac6d68af6bd4","refusal_reason":null,"registered_at":"2026-07-14T09:05:27.904385+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"8b892236b4e367dec9415bbb6032921e8fdbc55e61ca26f9917021e2cf432e2a","refusal_reason":null,"registered_at":"2026-07-14T09:05:28.098274+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T09:05:28.296769+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T09:05:28.504716+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T09:05:28.793956+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T09:05:28.990580+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T09:05:29.184585+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T09:05:29.377104+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T09:05:29.577878+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : 1b4713a1bcc1e725
    ID             : c15c825da119fbc9
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 09:07:12.606793466 +0000 UTC
    End time       : 2026-07-14 09:07:12.6068213 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #1
    Trace ID       : 4fa0b49c8a26d974fda38af75f70ed42
    Parent ID      : 1b4713a1bcc1e725
    ID             : 3b611c6f3cbe2833
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 09:07:12.606936591 +0000 UTC
    End time       : 2026-07-14 09:07:12.606943091 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #2
    Trace ID       : 4fa0b49c8a26d974fda38af75f70ed42
    Parent ID      : 1b4713a1bcc1e725
    ID             : d121385158ed1dac
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 09:07:12.606969758 +0000 UTC
    End time       : 2026-07-14 09:07:12.60697455 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #3
    Trace ID       : 4fa0b49c8a26d974fda38af75f70ed42
    Parent ID      :
    ID             : 1b4713a1bcc1e725
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-14 09:07:12.588586341 +0000 UTC
    End time       : 2026-07-14 09:07:12.6070383 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.29:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.29:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(45612)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 09:05:27,176", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 09:05:30,038", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 09:05:32,106", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7788cd9ec36a46dbabea717deee33d35", "trace_id": "36ac456cf8560101fe36d60f9232fe48", "span_id": "6f5c2d7c3213ce87", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.695, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:05:32,616", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7f138848ab2848d9a8487f72ff8ed9ee", "trace_id": "a119a0c3f3dce0316f65ee1d171e6017", "span_id": "947b4c0cdd8a7fb7"}
{"ts": "2026-07-14 09:05:32,626", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7f138848ab2848d9a8487f72ff8ed9ee", "trace_id": "a119a0c3f3dce0316f65ee1d171e6017", "span_id": "947b4c0cdd8a7fb7"}
{"ts": "2026-07-14 09:05:32,635", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7f138848ab2848d9a8487f72ff8ed9ee", "trace_id": "a119a0c3f3dce0316f65ee1d171e6017", "span_id": "947b4c0cdd8a7fb7"}
{"ts": "2026-07-14 09:05:32,635", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7f138848ab2848d9a8487f72ff8ed9ee", "trace_id": "a119a0c3f3dce0316f65ee1d171e6017", "span_id": "947b4c0cdd8a7fb7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.149, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:05:33,715", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-06b72ce678b1451483d6d0ac6ce1dbf3", "trace_id": "8ec9b6dce287cd995383780ba2daacb2", "span_id": "edf81c2781acac3e", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.098, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 09:05:33,774", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 401 Unauthorized\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,778", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/.well-known/oauth-protected-resource/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,781", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://192.88.99.9:9000/.well-known/oauth-authorization-server \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,782", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://192.88.99.9:9000/token \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,963", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,963", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Received session ID: 8e6e23f2c9c9442fa573e6cac2ccba9c", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,964", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Negotiated protocol version: 2025-11-25", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 202 Accepted\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,966", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,968", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,969", "level": "INFO", "logger": "httpx", "message": "HTTP Request: DELETE http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,970", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "GET stream disconnected, reconnecting in 1000ms...", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3"}
{"ts": "2026-07-14 09:05:33,970", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-08295057513843ef9a76d8ae449448a0", "trace_id": "0f019af19922595b343a86d337a12550", "span_id": "4b426eddba69c9a3", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 207.757, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 09:05:37,098", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d11cfa68745e4697a3e60e91fb3b5b1a", "trace_id": "bb4c58ba4fc3771703a1d0634685b70e", "span_id": "e52d69fae084ce3e", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.109, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:05:37,386", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-8dacc05eb7704358bb100c13f2afb69f", "trace_id": "159076c2f28a59a2f1a6cbf67221bcd2", "span_id": "e484d17516be4b3a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:37,386", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8dacc05eb7704358bb100c13f2afb69f", "trace_id": "159076c2f28a59a2f1a6cbf67221bcd2", "span_id": "e484d17516be4b3a", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 4.718, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 09:05:40,834", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-46e7bc04e03f46db828ecdb6541d98f1", "trace_id": "6ff3cdf9bb8c2f4d3271c3dc5c1d0fa8", "span_id": "32214b6e6585103f", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:40,835", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-46e7bc04e03f46db828ecdb6541d98f1", "trace_id": "6ff3cdf9bb8c2f4d3271c3dc5c1d0fa8", "span_id": "32214b6e6585103f", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.234, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 09:05:42,516", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d6f91af28782410c9dc6da572c310e4f", "trace_id": "dfdd67d4ede0e52e2e62536013fcd565", "span_id": "21194fe97ea9c0b1", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:42,516", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d6f91af28782410c9dc6da572c310e4f", "trace_id": "dfdd67d4ede0e52e2e62536013fcd565", "span_id": "21194fe97ea9c0b1", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.123, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:05:42,611", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bb318408977e4405bf1b525ddc904eed", "trace_id": "24e6c4ac3b3033b0254844d278c74dc9", "span_id": "1e84ca1501e2773f"}
{"ts": "2026-07-14 09:05:42,620", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bb318408977e4405bf1b525ddc904eed", "trace_id": "24e6c4ac3b3033b0254844d278c74dc9", "span_id": "1e84ca1501e2773f"}
{"ts": "2026-07-14 09:05:42,630", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bb318408977e4405bf1b525ddc904eed", "trace_id": "24e6c4ac3b3033b0254844d278c74dc9", "span_id": "1e84ca1501e2773f"}
{"ts": "2026-07-14 09:05:42,631", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bb318408977e4405bf1b525ddc904eed", "trace_id": "24e6c4ac3b3033b0254844d278c74dc9", "span_id": "1e84ca1501e2773f", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.199, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:05:51,323", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-55fe81f8b6d046d7b927385c2cc6a80c", "trace_id": "314ab203ae0bdff729c4eb1f5dd33cd2", "span_id": "849a51ae0d4b2019", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:51,323", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-55fe81f8b6d046d7b927385c2cc6a80c", "trace_id": "314ab203ae0bdff729c4eb1f5dd33cd2", "span_id": "849a51ae0d4b2019", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.717, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:51,926", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-037340abb9574638b3cbe7216ab4c125", "trace_id": "a3bf7ddec18032c846cdf910d584e498", "span_id": "a476853c788788a9", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:51,926", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-037340abb9574638b3cbe7216ab4c125", "trace_id": "a3bf7ddec18032c846cdf910d584e498", "span_id": "a476853c788788a9", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.099, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:52,104", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7a20ab94ff584d3a81268c44d3832031", "trace_id": "36896b0e45bd1bfab61f5499b256a3ed", "span_id": "45de8d4b61c80668", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.192, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:05:52,558", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-bdebb6cf7d2a4cb3b5f32357e8f32538", "trace_id": "92040bc827a3e20ae3f2aa480fcf4f25", "span_id": "cddceaf1ad5ea1c5", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:52,558", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bdebb6cf7d2a4cb3b5f32357e8f32538", "trace_id": "92040bc827a3e20ae3f2aa480fcf4f25", "span_id": "cddceaf1ad5ea1c5", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.118, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:52,612", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d3285bcd9740420f82b06bffe5c31b7d", "trace_id": "99db4d925ffd3d8030cfc7267d0743bc", "span_id": "dbff6e238a450351"}
{"ts": "2026-07-14 09:05:52,623", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d3285bcd9740420f82b06bffe5c31b7d", "trace_id": "99db4d925ffd3d8030cfc7267d0743bc", "span_id": "dbff6e238a450351"}
{"ts": "2026-07-14 09:05:52,631", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d3285bcd9740420f82b06bffe5c31b7d", "trace_id": "99db4d925ffd3d8030cfc7267d0743bc", "span_id": "dbff6e238a450351"}
{"ts": "2026-07-14 09:05:52,632", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d3285bcd9740420f82b06bffe5c31b7d", "trace_id": "99db4d925ffd3d8030cfc7267d0743bc", "span_id": "dbff6e238a450351", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.293, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:05:52,683", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-206dc667af0742d5aec7f79958f1b84e", "trace_id": "8aa51fba79b670a9bef1a5256fda9162", "span_id": "b86c25109b714f94", "http_method": "POST", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 9.476, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:52,696", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-1c86e4101add4e14b2e98e7b1da26a9a", "trace_id": "25c93f0dcfb207a790f4070fb33d2b07", "span_id": "6e5bc1fefc510718", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:52,696", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1c86e4101add4e14b2e98e7b1da26a9a", "trace_id": "25c93f0dcfb207a790f4070fb33d2b07", "span_id": "6e5bc1fefc510718", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.895, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:52,706", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-a1ba040a44474981ad4f49097e1f03f8", "trace_id": "44d92954d5156c0893ae6d1209c86d8b", "span_id": "2c48c5324466c481", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "b5006e1d-242d-43f9-90fd-f66ce3c3a420", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:52,706", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a1ba040a44474981ad4f49097e1f03f8", "trace_id": "44d92954d5156c0893ae6d1209c86d8b", "span_id": "2c48c5324466c481", "http_method": "GET", "http_path": "/api/v1/conversations/b5006e1d-242d-43f9-90fd-f66ce3c3a420/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 7.04, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:56,029", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://litellm:4000/chat/completions \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d42b27237d794021af0700068ecc529b", "trace_id": "afa5bcbbf6ef64255d6d5c7f5fd05b8d", "span_id": "910f8c6823b55ca4"}
{"ts": "2026-07-14 09:05:56,044", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d42b27237d794021af0700068ecc529b", "trace_id": "afa5bcbbf6ef64255d6d5c7f5fd05b8d", "span_id": "910f8c6823b55ca4", "http_method": "POST", "http_path": "/api/v1/conversations/b5006e1d-242d-43f9-90fd-f66ce3c3a420/turns", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 3292.046, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:56,054", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-4a30f6960fc24c1facaee5db0417bf6e", "trace_id": "9f582e79eea99c8a9d9893086471966d", "span_id": "e943987e66bac10c", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:56,055", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4a30f6960fc24c1facaee5db0417bf6e", "trace_id": "9f582e79eea99c8a9d9893086471966d", "span_id": "e943987e66bac10c", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.544, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:56,058", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-7ab864708afa4d398b4faea548df9524", "trace_id": "33875610b9e3677dde4e46c5194c72d3", "span_id": "ba91579dbf57971a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "b5006e1d-242d-43f9-90fd-f66ce3c3a420", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:56,058", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7ab864708afa4d398b4faea548df9524", "trace_id": "33875610b9e3677dde4e46c5194c72d3", "span_id": "ba91579dbf57971a", "http_method": "GET", "http_path": "/api/v1/conversations/b5006e1d-242d-43f9-90fd-f66ce3c3a420/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.292, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:56,588", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-823bca65622947e9904bb00d11394846", "trace_id": "7aba779ca770b1770134602a36555a05", "span_id": "5d259c32705be03a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:56,589", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-823bca65622947e9904bb00d11394846", "trace_id": "7aba779ca770b1770134602a36555a05", "span_id": "5d259c32705be03a", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.041, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:56,593", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-bc648abf075f44a5b31c6b0bdad4bbb5", "trace_id": "e24fdefc6ceedc9ba74ee1c5977909f1", "span_id": "8e3f9595997b2266", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "b5006e1d-242d-43f9-90fd-f66ce3c3a420", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:56,593", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bc648abf075f44a5b31c6b0bdad4bbb5", "trace_id": "e24fdefc6ceedc9ba74ee1c5977909f1", "span_id": "8e3f9595997b2266", "http_method": "GET", "http_path": "/api/v1/conversations/b5006e1d-242d-43f9-90fd-f66ce3c3a420/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.61, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:56,684", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-9bf028f946714c148f3a118d845a5e97", "trace_id": "5a86571b6514b47722736e7b608f26af", "span_id": "bf2d2426dd40fe03", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "b5006e1d-242d-43f9-90fd-f66ce3c3a420", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:56,684", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9bf028f946714c148f3a118d845a5e97", "trace_id": "5a86571b6514b47722736e7b608f26af", "span_id": "bf2d2426dd40fe03", "http_method": "GET", "http_path": "/api/v1/conversations/b5006e1d-242d-43f9-90fd-f66ce3c3a420/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 3.229, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:05:57,236", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-a07ec5bb7ea240c88ad57fcf69a93ed7", "trace_id": "463b8d5e5077f918ad6d5e468732cb64", "span_id": "afedb16ab8b50a62", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:05:57,237", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a07ec5bb7ea240c88ad57fcf69a93ed7", "trace_id": "463b8d5e5077f918ad6d5e468732cb64", "span_id": "afedb16ab8b50a62", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.055, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:02,529", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-4ad2ae8760874df5836a2b972287373f", "trace_id": "ed633846483d04d6ca69f2509c7758eb", "span_id": "e7b352032cd99378", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:02,529", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4ad2ae8760874df5836a2b972287373f", "trace_id": "ed633846483d04d6ca69f2509c7758eb", "span_id": "e7b352032cd99378", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.75, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:02,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1244f5d19ad142e5b780dab06b0cb170", "trace_id": "fc3dcae61dde449fc8154f31758790b7", "span_id": "4688374fef5960f5"}
{"ts": "2026-07-14 09:06:02,606", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1244f5d19ad142e5b780dab06b0cb170", "trace_id": "fc3dcae61dde449fc8154f31758790b7", "span_id": "4688374fef5960f5"}
{"ts": "2026-07-14 09:06:02,615", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1244f5d19ad142e5b780dab06b0cb170", "trace_id": "fc3dcae61dde449fc8154f31758790b7", "span_id": "4688374fef5960f5"}
{"ts": "2026-07-14 09:06:02,615", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1244f5d19ad142e5b780dab06b0cb170", "trace_id": "fc3dcae61dde449fc8154f31758790b7", "span_id": "4688374fef5960f5", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.212, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:02,724", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-084954b83533452381dac6cff1b390a1", "trace_id": "890aa13387ee8cb1af09450910b2e03f", "span_id": "d1b01c92c3381701", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:02,724", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-084954b83533452381dac6cff1b390a1", "trace_id": "890aa13387ee8cb1af09450910b2e03f", "span_id": "d1b01c92c3381701", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.664, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:07,088", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a029c6b102fd4564b3d94b90c0d4988f", "trace_id": "a40b8b26ec0d2af64f48245d609b5bb0", "span_id": "caf0d3f2f51ee794", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.198, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:12,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bbc818ad6bf141179a0ac6ec3889778e", "trace_id": "aaeccba7e63caff68c6cc50a7870fcea", "span_id": "fc8b939ef7ceb448"}
{"ts": "2026-07-14 09:06:12,607", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bbc818ad6bf141179a0ac6ec3889778e", "trace_id": "aaeccba7e63caff68c6cc50a7870fcea", "span_id": "fc8b939ef7ceb448"}
{"ts": "2026-07-14 09:06:12,615", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bbc818ad6bf141179a0ac6ec3889778e", "trace_id": "aaeccba7e63caff68c6cc50a7870fcea", "span_id": "fc8b939ef7ceb448"}
{"ts": "2026-07-14 09:06:12,615", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bbc818ad6bf141179a0ac6ec3889778e", "trace_id": "aaeccba7e63caff68c6cc50a7870fcea", "span_id": "fc8b939ef7ceb448", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.195, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:17,804", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c28a9e75da83487c9f665a8aee69c4eb", "trace_id": "0f8674b21fd99ad59620b637a844a4d3", "span_id": "dd0473ac2ad5b7af", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:17,804", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c28a9e75da83487c9f665a8aee69c4eb", "trace_id": "0f8674b21fd99ad59620b637a844a4d3", "span_id": "dd0473ac2ad5b7af", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.598, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:22,088", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7bbebae890e94383a7b3f32cbeccf82e", "trace_id": "f3e2ae43401b558606e21b310f5141be", "span_id": "b768f7d8d438fec0", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.253, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:22,602", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-56d900d2b8e24c879c2ead0d4d471be2", "trace_id": "0059b0658c9bc4f68e494cb435e80d2c", "span_id": "7122ea44a6170d3d"}
{"ts": "2026-07-14 09:06:22,612", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-56d900d2b8e24c879c2ead0d4d471be2", "trace_id": "0059b0658c9bc4f68e494cb435e80d2c", "span_id": "7122ea44a6170d3d"}
{"ts": "2026-07-14 09:06:22,620", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-56d900d2b8e24c879c2ead0d4d471be2", "trace_id": "0059b0658c9bc4f68e494cb435e80d2c", "span_id": "7122ea44a6170d3d"}
{"ts": "2026-07-14 09:06:22,621", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-56d900d2b8e24c879c2ead0d4d471be2", "trace_id": "0059b0658c9bc4f68e494cb435e80d2c", "span_id": "7122ea44a6170d3d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.616, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:32,597", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-27fe00696b33464192ee416e9216bc83", "trace_id": "6497a677f27657f1148e268558f4814b", "span_id": "10683e98a69f077c"}
{"ts": "2026-07-14 09:06:32,606", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-27fe00696b33464192ee416e9216bc83", "trace_id": "6497a677f27657f1148e268558f4814b", "span_id": "10683e98a69f077c"}
{"ts": "2026-07-14 09:06:32,615", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-27fe00696b33464192ee416e9216bc83", "trace_id": "6497a677f27657f1148e268558f4814b", "span_id": "10683e98a69f077c"}
{"ts": "2026-07-14 09:06:32,616", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-27fe00696b33464192ee416e9216bc83", "trace_id": "6497a677f27657f1148e268558f4814b", "span_id": "10683e98a69f077c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.21, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:34,270", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c8192157813542149ec0e75467ae2431", "trace_id": "11abc50be8ce766b1db441a0393df99d", "span_id": "a9d43374ede40b24", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,270", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c8192157813542149ec0e75467ae2431", "trace_id": "11abc50be8ce766b1db441a0393df99d", "span_id": "a9d43374ede40b24", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.261, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:34,513", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-2f7ec40f3cf74144b0973f4716268917", "trace_id": "c7ba023377f6743300dd3a546ed51a16", "span_id": "f20fce86ae8d12ca", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,513", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2f7ec40f3cf74144b0973f4716268917", "trace_id": "c7ba023377f6743300dd3a546ed51a16", "span_id": "f20fce86ae8d12ca", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 9.335, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:34,534", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-664bd8e08a7a496d8d5939b9f225e39f", "trace_id": "872673cfb23e4c1af9c76145f88d4e52", "span_id": "65628b1762783778", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,534", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-664bd8e08a7a496d8d5939b9f225e39f", "trace_id": "872673cfb23e4c1af9c76145f88d4e52", "span_id": "65628b1762783778", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.321, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:34,590", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-2acf8bea0f6b4d00a3ef085241f78482", "trace_id": "0a9871616378f380fedc5b4f2de53f8a", "span_id": "0b09402c4536c5c3", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,590", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2acf8bea0f6b4d00a3ef085241f78482", "trace_id": "0a9871616378f380fedc5b4f2de53f8a", "span_id": "0b09402c4536c5c3", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 81.163, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:34,593", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-87e0d6a830864f8395deee4b2e8c0ce8", "trace_id": "d9f040c6aeed8c853c89617c855210fc", "span_id": "16ce164617a4c4e2", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,593", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-87e0d6a830864f8395deee4b2e8c0ce8", "trace_id": "d9f040c6aeed8c853c89617c855210fc", "span_id": "16ce164617a4c4e2", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 76.879, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:34,593", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-88a42e94af664e899437109a6a30ee33", "trace_id": "2b0fb3eef1eecf5006ddbd1ffd0fa059", "span_id": "66cd8b91382ea09d", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,593", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-88a42e94af664e899437109a6a30ee33", "trace_id": "2b0fb3eef1eecf5006ddbd1ffd0fa059", "span_id": "66cd8b91382ea09d", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 76.963, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:34,593", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-3d6526f8f0ea4e10b75ba249baaa7bda", "trace_id": "1e968795b8f4768b7877fac156e0d3ce", "span_id": "2487c6bc82703be2", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,593", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3d6526f8f0ea4e10b75ba249baaa7bda", "trace_id": "1e968795b8f4768b7877fac156e0d3ce", "span_id": "2487c6bc82703be2", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 76.646, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:34,595", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-1a3679d534fb46a2838ef301c44f2b56", "trace_id": "9aaac563c5651808c497438094815aaf", "span_id": "799615f2a7375bbc", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:34,595", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1a3679d534fb46a2838ef301c44f2b56", "trace_id": "9aaac563c5651808c497438094815aaf", "span_id": "799615f2a7375bbc", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 78.212, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:37,083", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-99b37be9f70c42e6b8c36708fe542c33", "trace_id": "b84ce262be47a4645930823a67c319e5", "span_id": "5836c5a3a1deffa4", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.206, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:38,163", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-41a6029cfc2a4682b63e956f7a1dc7c7", "trace_id": "4347507a52dd9a56c05a90f5a4e9a113", "span_id": "9be25b9d2ed7f10b", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:38,163", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-41a6029cfc2a4682b63e956f7a1dc7c7", "trace_id": "4347507a52dd9a56c05a90f5a4e9a113", "span_id": "9be25b9d2ed7f10b", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.085, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 09:06:40,271", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-80018b5479b2474f825bb4b2a731fce5", "trace_id": "89aac9e56aba2d65d4cdf9c7de2540e2", "span_id": "0f7d4e50ae74c17a", "tenant_id": "proof-foreign", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#31316dc7-5ad0-515e-a333-7ec9301118c7", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:40,271", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-80018b5479b2474f825bb4b2a731fce5", "trace_id": "89aac9e56aba2d65d4cdf9c7de2540e2", "span_id": "0f7d4e50ae74c17a", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.156, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:40,860", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-4dedbda7f8df409c9e19c083ae303523", "trace_id": "5788270fa93126770d3b3bce72cd01a7", "span_id": "65d89b48a0eba60b", "tenant_id": "proof-foreign", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#31316dc7-5ad0-515e-a333-7ec9301118c7", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 09:06:40,860", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4dedbda7f8df409c9e19c083ae303523", "trace_id": "5788270fa93126770d3b3bce72cd01a7", "span_id": "65d89b48a0eba60b", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.026, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 09:06:42,594", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ac608bda91a94128b55bc63880dbae1b", "trace_id": "17a9fcf1cb7b65dcf8d34bc0828b1f12", "span_id": "90139d8980a192e8"}
{"ts": "2026-07-14 09:06:42,602", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ac608bda91a94128b55bc63880dbae1b", "trace_id": "17a9fcf1cb7b65dcf8d34bc0828b1f12", "span_id": "90139d8980a192e8"}
{"ts": "2026-07-14 09:06:42,610", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ac608bda91a94128b55bc63880dbae1b", "trace_id": "17a9fcf1cb7b65dcf8d34bc0828b1f12", "span_id": "90139d8980a192e8"}
{"ts": "2026-07-14 09:06:42,611", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ac608bda91a94128b55bc63880dbae1b", "trace_id": "17a9fcf1cb7b65dcf8d34bc0828b1f12", "span_id": "90139d8980a192e8", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.024, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:52,084", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-046d7bffe40143da8a96020f0f91d3b6", "trace_id": "f60220e9a3be9e52660193441c883986", "span_id": "f76d0080d3b260e9", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.264, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:06:52,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c007a04931f840a48a75700b48a34378", "trace_id": "709add1449467e3f7a0cf35d038f8241", "span_id": "5209ebf9650af664"}
{"ts": "2026-07-14 09:06:52,608", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c007a04931f840a48a75700b48a34378", "trace_id": "709add1449467e3f7a0cf35d038f8241", "span_id": "5209ebf9650af664"}
{"ts": "2026-07-14 09:06:52,618", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c007a04931f840a48a75700b48a34378", "trace_id": "709add1449467e3f7a0cf35d038f8241", "span_id": "5209ebf9650af664"}
{"ts": "2026-07-14 09:06:52,618", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c007a04931f840a48a75700b48a34378", "trace_id": "709add1449467e3f7a0cf35d038f8241", "span_id": "5209ebf9650af664", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.484, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:07:02,597", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-54d84e22d3334a20a38909d091877381", "trace_id": "84a754c027069d73c1acf5197d3bfc5e", "span_id": "1ebe667691a095f1"}
{"ts": "2026-07-14 09:07:02,607", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-54d84e22d3334a20a38909d091877381", "trace_id": "84a754c027069d73c1acf5197d3bfc5e", "span_id": "1ebe667691a095f1"}
{"ts": "2026-07-14 09:07:02,616", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-54d84e22d3334a20a38909d091877381", "trace_id": "84a754c027069d73c1acf5197d3bfc5e", "span_id": "1ebe667691a095f1"}
{"ts": "2026-07-14 09:07:02,616", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-54d84e22d3334a20a38909d091877381", "trace_id": "84a754c027069d73c1acf5197d3bfc5e", "span_id": "1ebe667691a095f1", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.109, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:07:07,082", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9de8e2f76bd8440eabe23cab780268a4", "trace_id": "8f6543e204de43352c1e881ae155a642", "span_id": "076cf961dfd23e78", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.353, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:07:12,591", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-149d1d5dd0fe4df7810d666a9fbbb748", "trace_id": "4fa0b49c8a26d974fda38af75f70ed42", "span_id": "1b4713a1bcc1e725"}
{"ts": "2026-07-14 09:07:12,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-149d1d5dd0fe4df7810d666a9fbbb748", "trace_id": "4fa0b49c8a26d974fda38af75f70ed42", "span_id": "1b4713a1bcc1e725"}
{"ts": "2026-07-14 09:07:12,606", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-149d1d5dd0fe4df7810d666a9fbbb748", "trace_id": "4fa0b49c8a26d974fda38af75f70ed42", "span_id": "1b4713a1bcc1e725"}
{"ts": "2026-07-14 09:07:12,606", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-149d1d5dd0fe4df7810d666a9fbbb748", "trace_id": "4fa0b49c8a26d974fda38af75f70ed42", "span_id": "1b4713a1bcc1e725", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 17.887, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:07:22,084", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9fc51f2c7bb449ce847a8e5ac40a6f83", "trace_id": "173caed9436d9bb067709d8741e61124", "span_id": "c0fc41db291fcb8b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.225, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 09:07:22,598", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-884c2cc2330c4401b637a0062a952aef", "trace_id": "9221817b6cc1294e6018be97ccc48bde", "span_id": "cb2de8707135bf95"}
{"ts": "2026-07-14 09:07:22,607", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-884c2cc2330c4401b637a0062a952aef", "trace_id": "9221817b6cc1294e6018be97ccc48bde", "span_id": "cb2de8707135bf95"}
{"ts": "2026-07-14 09:07:22,615", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-884c2cc2330c4401b637a0062a952aef", "trace_id": "9221817b6cc1294e6018be97ccc48bde", "span_id": "cb2de8707135bf95"}
{"ts": "2026-07-14 09:07:22,616", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-884c2cc2330c4401b637a0062a952aef", "trace_id": "9221817b6cc1294e6018be97ccc48bde", "span_id": "cb2de8707135bf95", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.17, "client_addr": "10.244.0.1"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T10:39:50Z)

- Failed step: `browser login for approver.dana failed (rc=3): {
  "error": "not_authenticated_after_login",
  "url": "https://127.0.0.1:8444/",
  "dom_excerpt": "<html><head><meta name=\"color-scheme\" content=\"light dark\"></head><body><pre style=\"word-wrap: break-word; white-space: pre-wrap;\">AgentOS error: scope_not_held</pre></body></html>"
}`
- last API response (HTTP 200):
```json
{"tools":[{"name":"probe_write","title":null,"description":"Append a per-call nonce to the proof-local invocation ledger and return the nonce plus the ledger line count. Business-side-effect-free: the ledger is proof instrumentation for the ADR-014 four-eyes approval proof (the independent observer that makes 'zero execution' provable), not a business write.","inputSchema":{"properties":{"nonce":{"title":"Nonce","type":"string"}},"required":["nonce"],"title":"probe_writeArguments","type":"object"},"outputSchema":{"additionalProperties":true,"title":"probe_writeDictOutput","type":"object"},"icons":null,"annotations":null,"_meta":null,"execution":null}]}
```
- conversation.% chain rows (tail 10 — digest-only):
```
conversation.turn_completed|{"agent_run_id": "agent-run-f68183ce6246485883f7f54514e1b807", "answer_bytes": 160, "answer_sha256": "5b15541ce1be7ae4c4384168015b90d45ef566d682ae53b4a42db7ee77fa66c6", "completion_tokens": 35, "conversation_id": "23598fe7-5894-4231-98bf-a960a14f345b", "prompt_tokens": 970, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "seq": 1, "turn_id": "dbe100f0-ec5c-4d51-b07e-b00382afe051", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
conversation.created|{"agent_id": "bank-analyst", "conversation_id": "23598fe7-5894-4231-98bf-a960a14f345b", "created_at": "2026-07-14T10:34:39.566210+00:00", "creator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- conversations operational records (tail 6 — no plaintext):
```
23598fe7-5894-4231-98bf-a960a14f345b | active | turns=1 | tokens=1005 | in_progress=false
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
agent.run.completed|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "answer_bytes": 160, "answer_sha256": "5b15541ce1be7ae4c4384168015b90d45ef566d682ae53b4a42db7ee77fa66c6", "completion_tokens_total": 35, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prompt_tokens_total": 970, "run_id": "agent-run-f68183ce6246485883f7f54514e1b807", "steps_used": 1}
agent.run.started|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "max_steps": 6, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prior_context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "prior_context_turns": 0, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "run_id": "agent-run-f68183ce6246485883f7f54514e1b807", "token_budget": 60000, "wall_clock_s": 300.0}
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
agent-run-f68183ce6246485883f7f54514e1b807-s0 | cognic-tier1-proof-m85c | openai/gpt-4o | external=true | resolved | ok
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m10:33:12 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m10:33:12 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#       'This feature doesn't meet my needs because...'       #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:45062 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:41606 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:42278 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35536 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33978 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47960 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36544 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:56436 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39616 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.29:38076 - "POST /chat/completions HTTP/1.1" 200 OK
INFO:     10.244.0.1:60922 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39070 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:40918 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55476 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:48982 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:34292 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46006 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55600 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33158 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:43370 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51150 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:41304 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46568 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:58200 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47676 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55398 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54542 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33694 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35528 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:50550 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35952 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53810 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:48420 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:56792 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:50350 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:42712 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33894 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55602 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57834 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:60990 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:56892 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
{"approval_verified": false, "block_kind": null, "data_classes": ["operational_telemetry"], "purpose": "agent_run_notes", "record_id": "248e51b4-47f6-4dc3-afe8-ed5ba03641a7", "redacted_value_digest": "e2a129e32081fd2c1afb58699d69f24c64a57cc62f3e2e8e9872308ecea5b7a0", "retention_until": null, "subject_ref": "human:https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "tier": "task", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"3052377cc352affb7526252b560033998a6df16972357b10d9e526b6d76760d8","refusal_reason":null,"registered_at":"2026-07-14T10:34:12.597934+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"f57708a228f847cf5027984cd5d7f76cef1d4c34a5472d33b9ad489f4ca3abdd","refusal_reason":null,"registered_at":"2026-07-14T10:34:12.789884+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T10:34:12.987380+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T10:34:13.273450+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T10:34:13.474824+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T10:34:13.673300+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T10:34:13.869037+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T10:34:14.061917+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T10:34:14.262567+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : 79dfeb6b4bd33c84
    ID             : 104e47b05e01c903
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 10:39:37.463286256 +0000 UTC
    End time       : 2026-07-14 10:39:37.463312048 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #5
    Trace ID       : f16d915874556f671fd637ebb2330e66
    Parent ID      : 79dfeb6b4bd33c84
    ID             : 2363b479244a939d
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 10:39:37.463451464 +0000 UTC
    End time       : 2026-07-14 10:39:37.463458298 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #6
    Trace ID       : f16d915874556f671fd637ebb2330e66
    Parent ID      : 79dfeb6b4bd33c84
    ID             : ab721a5081049ba3
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 10:39:37.463492423 +0000 UTC
    End time       : 2026-07-14 10:39:37.463497048 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #7
    Trace ID       : f16d915874556f671fd637ebb2330e66
    Parent ID      :
    ID             : 79dfeb6b4bd33c84
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-14 10:39:37.443828131 +0000 UTC
    End time       : 2026-07-14 10:39:37.463561256 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.29:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.29:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(35406)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
{"ts": "2026-07-14 10:35:16,148", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-93c324544ee04fd8bcb86e43cfe30dfd", "trace_id": "9a593d4e1f9c6acecb833e5f73d9a9ff", "span_id": "41bc835e58e41aae", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,148", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-93c324544ee04fd8bcb86e43cfe30dfd", "trace_id": "9a593d4e1f9c6acecb833e5f73d9a9ff", "span_id": "41bc835e58e41aae", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.569, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 10:35:16,387", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-0da649b9b56b46238aecc9a99afb7086", "trace_id": "ad21ec293efc65753a7980127d47121a", "span_id": "5d8ab7a77592dbab", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,387", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0da649b9b56b46238aecc9a99afb7086", "trace_id": "ad21ec293efc65753a7980127d47121a", "span_id": "5d8ab7a77592dbab", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 13.002, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 10:35:16,390", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-343f9f0a8c624da7b5ad1d2fb2db8444", "trace_id": "3f43da8085121245700f6da68eed6cbd", "span_id": "12937be3d5a1e768", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,390", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-343f9f0a8c624da7b5ad1d2fb2db8444", "trace_id": "3f43da8085121245700f6da68eed6cbd", "span_id": "12937be3d5a1e768", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 8.129, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 10:35:16,467", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-e72423de2d394b099c41cd76b22491f0", "trace_id": "0b0753039ad18e8a858c477954131b23", "span_id": "e14019a8ffcec63a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e72423de2d394b099c41cd76b22491f0", "trace_id": "0b0753039ad18e8a858c477954131b23", "span_id": "e14019a8ffcec63a", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 84.168, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-969985b1e4234fc1a8aac06a6a19bc7c", "trace_id": "681d04e91fb01944731e7850c76b1a10", "span_id": "7655ebb942fa1c79", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-969985b1e4234fc1a8aac06a6a19bc7c", "trace_id": "681d04e91fb01944731e7850c76b1a10", "span_id": "7655ebb942fa1c79", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 83.399, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-9186fe510d96495b8ec1791eaab4d2b9", "trace_id": "a929c9794dfbe920970b6aaaebeee7bd", "span_id": "9b71ed0df04bbd86", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9186fe510d96495b8ec1791eaab4d2b9", "trace_id": "a929c9794dfbe920970b6aaaebeee7bd", "span_id": "9b71ed0df04bbd86", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 85.511, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-bd3f1c8fec8f4d079b9f67da6ede8755", "trace_id": "0fdb754b0fc022a530dba4aa04163f87", "span_id": "e12f146b2cdebdc5", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bd3f1c8fec8f4d079b9f67da6ede8755", "trace_id": "0fdb754b0fc022a530dba4aa04163f87", "span_id": "e12f146b2cdebdc5", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 84.504, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 10:35:16,469", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-78d66647938a438c99fa794adae82f51", "trace_id": "39b86d602b63cd47075e11da595d6dd7", "span_id": "296bc89ea20b09f0", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:16,469", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-78d66647938a438c99fa794adae82f51", "trace_id": "39b86d602b63cd47075e11da595d6dd7", "span_id": "296bc89ea20b09f0", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 85.775, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 10:35:17,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ffefdba732af43379b8a1d36738e2415", "trace_id": "aaad3a48e127aef8ce1d34e4a9484dc3", "span_id": "7023d57c7f2845f8"}
{"ts": "2026-07-14 10:35:17,460", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ffefdba732af43379b8a1d36738e2415", "trace_id": "aaad3a48e127aef8ce1d34e4a9484dc3", "span_id": "7023d57c7f2845f8"}
{"ts": "2026-07-14 10:35:17,468", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ffefdba732af43379b8a1d36738e2415", "trace_id": "aaad3a48e127aef8ce1d34e4a9484dc3", "span_id": "7023d57c7f2845f8"}
{"ts": "2026-07-14 10:35:17,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ffefdba732af43379b8a1d36738e2415", "trace_id": "aaad3a48e127aef8ce1d34e4a9484dc3", "span_id": "7023d57c7f2845f8", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.435, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:20,039", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-60da1ddf396742cd84b61565ece75384", "trace_id": "1d48171eff056c8b39ff25d94249aa02", "span_id": "da91f5c27a5dc617", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:20,039", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-60da1ddf396742cd84b61565ece75384", "trace_id": "1d48171eff056c8b39ff25d94249aa02", "span_id": "da91f5c27a5dc617", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.037, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 10:35:21,912", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-44156bedbb8149e6bb7889a26d04f54e", "trace_id": "5d88f40a29bc5aa54c61eada76845657", "span_id": "b4496e1fb0a91deb", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.115, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:22,139", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-eb7f11423f094bfca5e0a3e26573a806", "trace_id": "337676bedac37a42181318c8342caaf0", "span_id": "0fcfd0ae65130759", "tenant_id": "proof-foreign", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#31316dc7-5ad0-515e-a333-7ec9301118c7", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:22,139", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-eb7f11423f094bfca5e0a3e26573a806", "trace_id": "337676bedac37a42181318c8342caaf0", "span_id": "0fcfd0ae65130759", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.649, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 10:35:22,732", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c2036da5d2cf440089a0d4d816a90cb1", "trace_id": "64c5a8f5c432fabf66a9d6df9c6f82b0", "span_id": "e58925c8fc65c98f", "tenant_id": "proof-foreign", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#31316dc7-5ad0-515e-a333-7ec9301118c7", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:22,732", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c2036da5d2cf440089a0d4d816a90cb1", "trace_id": "64c5a8f5c432fabf66a9d6df9c6f82b0", "span_id": "e58925c8fc65c98f", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.79, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 10:35:27,449", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-77684a61a7e74a829cd4013fe4a641dc", "trace_id": "5427730c4d4dfc0d88728a55b36e361a", "span_id": "5a8cb730a203de71"}
{"ts": "2026-07-14 10:35:27,457", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-77684a61a7e74a829cd4013fe4a641dc", "trace_id": "5427730c4d4dfc0d88728a55b36e361a", "span_id": "5a8cb730a203de71"}
{"ts": "2026-07-14 10:35:27,466", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-77684a61a7e74a829cd4013fe4a641dc", "trace_id": "5427730c4d4dfc0d88728a55b36e361a", "span_id": "5a8cb730a203de71"}
{"ts": "2026-07-14 10:35:27,466", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-77684a61a7e74a829cd4013fe4a641dc", "trace_id": "5427730c4d4dfc0d88728a55b36e361a", "span_id": "5a8cb730a203de71", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.421, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:36,914", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-def76fb778b74382932b243cc0f263ce", "trace_id": "ed22d877c4669632a3de3fef16e3e3ff", "span_id": "2fc6f97923c843a8", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.235, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:37,447", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-72381cfb555c44d9b7784956e0bd705d", "trace_id": "ff2bdf600017ca02c542dd234f34bea2", "span_id": "c5372f8af8910e56"}
{"ts": "2026-07-14 10:35:37,457", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-72381cfb555c44d9b7784956e0bd705d", "trace_id": "ff2bdf600017ca02c542dd234f34bea2", "span_id": "c5372f8af8910e56"}
{"ts": "2026-07-14 10:35:37,466", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-72381cfb555c44d9b7784956e0bd705d", "trace_id": "ff2bdf600017ca02c542dd234f34bea2", "span_id": "c5372f8af8910e56"}
{"ts": "2026-07-14 10:35:37,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-72381cfb555c44d9b7784956e0bd705d", "trace_id": "ff2bdf600017ca02c542dd234f34bea2", "span_id": "c5372f8af8910e56", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.252, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:37,617", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d2219182edba4e4bb4c15e6f23cabf90", "trace_id": "0cff8f9ce430cee33126f2b2ddc51847", "span_id": "6b0f30555bb76573", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:37,617", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d2219182edba4e4bb4c15e6f23cabf90", "trace_id": "0cff8f9ce430cee33126f2b2ddc51847", "span_id": "6b0f30555bb76573", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.338, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:35:38,231", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-efcc4e16c59a4c5bb50f9a156f7be343", "trace_id": "89f4ce85d2089f2bfeb88e398fbd84fc", "span_id": "85fb0756fa0edc43", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:35:38,231", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-efcc4e16c59a4c5bb50f9a156f7be343", "trace_id": "89f4ce85d2089f2bfeb88e398fbd84fc", "span_id": "85fb0756fa0edc43", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.531, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:35:47,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2f345063d8d743a0a07e868799deec75", "trace_id": "b066b6400b80952b7fe95102a77d880e", "span_id": "a9b0c1a9a1c6048c"}
{"ts": "2026-07-14 10:35:47,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2f345063d8d743a0a07e868799deec75", "trace_id": "b066b6400b80952b7fe95102a77d880e", "span_id": "a9b0c1a9a1c6048c"}
{"ts": "2026-07-14 10:35:47,468", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2f345063d8d743a0a07e868799deec75", "trace_id": "b066b6400b80952b7fe95102a77d880e", "span_id": "a9b0c1a9a1c6048c"}
{"ts": "2026-07-14 10:35:47,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2f345063d8d743a0a07e868799deec75", "trace_id": "b066b6400b80952b7fe95102a77d880e", "span_id": "a9b0c1a9a1c6048c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.79, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:51,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3e0b06ed05c246e2aa9553e53a96f8eb", "trace_id": "72430d13109e62f73eedba240322ca8c", "span_id": "99518ba65632bd7b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.172, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:35:57,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-50178e58f9eb4d58a36146ae42be0126", "trace_id": "97fdac5874ea56e41eadbdefc803a0c9", "span_id": "64855dd18a960f77"}
{"ts": "2026-07-14 10:35:57,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-50178e58f9eb4d58a36146ae42be0126", "trace_id": "97fdac5874ea56e41eadbdefc803a0c9", "span_id": "64855dd18a960f77"}
{"ts": "2026-07-14 10:35:57,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-50178e58f9eb4d58a36146ae42be0126", "trace_id": "97fdac5874ea56e41eadbdefc803a0c9", "span_id": "64855dd18a960f77"}
{"ts": "2026-07-14 10:35:57,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-50178e58f9eb4d58a36146ae42be0126", "trace_id": "97fdac5874ea56e41eadbdefc803a0c9", "span_id": "64855dd18a960f77", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.521, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:06,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-012faa88697b4350bf5b972452ab1ee7", "trace_id": "2b597143ede1daf87e77a3880912706f", "span_id": "0ff00b71f4de7902", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.257, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:07,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d024d57fe6794ed281d8225422abe419", "trace_id": "5d324733280c392808dfeac8b09ad07a", "span_id": "207e8bfeb314f708"}
{"ts": "2026-07-14 10:36:07,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d024d57fe6794ed281d8225422abe419", "trace_id": "5d324733280c392808dfeac8b09ad07a", "span_id": "207e8bfeb314f708"}
{"ts": "2026-07-14 10:36:07,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d024d57fe6794ed281d8225422abe419", "trace_id": "5d324733280c392808dfeac8b09ad07a", "span_id": "207e8bfeb314f708"}
{"ts": "2026-07-14 10:36:07,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d024d57fe6794ed281d8225422abe419", "trace_id": "5d324733280c392808dfeac8b09ad07a", "span_id": "207e8bfeb314f708", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.679, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:17,455", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2b94ffd4f9a3458f9d90f94f342557fa", "trace_id": "e801f1e61b65bae22fbc3618575adac5", "span_id": "fbb18631de6736d5"}
{"ts": "2026-07-14 10:36:17,463", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2b94ffd4f9a3458f9d90f94f342557fa", "trace_id": "e801f1e61b65bae22fbc3618575adac5", "span_id": "fbb18631de6736d5"}
{"ts": "2026-07-14 10:36:17,471", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2b94ffd4f9a3458f9d90f94f342557fa", "trace_id": "e801f1e61b65bae22fbc3618575adac5", "span_id": "fbb18631de6736d5"}
{"ts": "2026-07-14 10:36:17,471", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2b94ffd4f9a3458f9d90f94f342557fa", "trace_id": "e801f1e61b65bae22fbc3618575adac5", "span_id": "fbb18631de6736d5", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.682, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:21,916", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8f1f4c59e9da40c99249d820ef65e8a3", "trace_id": "97f9333b9fe61ba976e9982af64836e6", "span_id": "252bb3378cf41ad0", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.204, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:27,454", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e4c849fc69424ac6a3de885b33aaf747", "trace_id": "60ea9e8e9ce7ef31a7d3467f5934335a", "span_id": "2ab51f681de6e879"}
{"ts": "2026-07-14 10:36:27,462", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e4c849fc69424ac6a3de885b33aaf747", "trace_id": "60ea9e8e9ce7ef31a7d3467f5934335a", "span_id": "2ab51f681de6e879"}
{"ts": "2026-07-14 10:36:27,471", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e4c849fc69424ac6a3de885b33aaf747", "trace_id": "60ea9e8e9ce7ef31a7d3467f5934335a", "span_id": "2ab51f681de6e879"}
{"ts": "2026-07-14 10:36:27,471", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e4c849fc69424ac6a3de885b33aaf747", "trace_id": "60ea9e8e9ce7ef31a7d3467f5934335a", "span_id": "2ab51f681de6e879", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.625, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:36,914", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-19e8a46723664233a7ff5fd4bf9f916e", "trace_id": "be8eaedc2d9263ce98dac8bbad7f5430", "span_id": "3b20a8e0dd09744f", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.217, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:37,454", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a45e9ba237bb4b11a2b16848f067e2ec", "trace_id": "251598e0106993d0722572f4ae7f1077", "span_id": "f42b26efda0cd38a"}
{"ts": "2026-07-14 10:36:37,463", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a45e9ba237bb4b11a2b16848f067e2ec", "trace_id": "251598e0106993d0722572f4ae7f1077", "span_id": "f42b26efda0cd38a"}
{"ts": "2026-07-14 10:36:37,472", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-a45e9ba237bb4b11a2b16848f067e2ec", "trace_id": "251598e0106993d0722572f4ae7f1077", "span_id": "f42b26efda0cd38a"}
{"ts": "2026-07-14 10:36:37,473", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a45e9ba237bb4b11a2b16848f067e2ec", "trace_id": "251598e0106993d0722572f4ae7f1077", "span_id": "f42b26efda0cd38a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.931, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:47,452", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b33c003e975e4fc6a3ede86199d52e85", "trace_id": "35bc3ae0954348183a5ea6c8a12b5830", "span_id": "c22c6c0ae8c4c2b0"}
{"ts": "2026-07-14 10:36:47,461", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b33c003e975e4fc6a3ede86199d52e85", "trace_id": "35bc3ae0954348183a5ea6c8a12b5830", "span_id": "c22c6c0ae8c4c2b0"}
{"ts": "2026-07-14 10:36:47,471", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-b33c003e975e4fc6a3ede86199d52e85", "trace_id": "35bc3ae0954348183a5ea6c8a12b5830", "span_id": "c22c6c0ae8c4c2b0"}
{"ts": "2026-07-14 10:36:47,471", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b33c003e975e4fc6a3ede86199d52e85", "trace_id": "35bc3ae0954348183a5ea6c8a12b5830", "span_id": "c22c6c0ae8c4c2b0", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.745, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:51,910", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f98e9596d6ef414b8b7a8a4c3058c7b0", "trace_id": "9af43688a128af4c814037e8f755da05", "span_id": "8055a615befb67cb", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.099, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:36:54,638", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-2d157c57a52848cb96757226e5f3aa61", "trace_id": "04214b68e7956f8918df403606dd9478", "span_id": "38c6ccf49b824c8f", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:36:54,638", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2d157c57a52848cb96757226e5f3aa61", "trace_id": "04214b68e7956f8918df403606dd9478", "span_id": "38c6ccf49b824c8f", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.136, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:36:57,455", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2ead9789cd534e3f91645c65de6bb3ab", "trace_id": "1902410558f910db895ec0cb7c69552b", "span_id": "9a002daf6c9fdcd1"}
{"ts": "2026-07-14 10:36:57,464", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2ead9789cd534e3f91645c65de6bb3ab", "trace_id": "1902410558f910db895ec0cb7c69552b", "span_id": "9a002daf6c9fdcd1"}
{"ts": "2026-07-14 10:36:57,472", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-2ead9789cd534e3f91645c65de6bb3ab", "trace_id": "1902410558f910db895ec0cb7c69552b", "span_id": "9a002daf6c9fdcd1"}
{"ts": "2026-07-14 10:36:57,472", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2ead9789cd534e3f91645c65de6bb3ab", "trace_id": "1902410558f910db895ec0cb7c69552b", "span_id": "9a002daf6c9fdcd1", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.529, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:06,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8e9e5e16588143cbae9a90e5689d6ce0", "trace_id": "dc5678e07e21c94d1dc38e6711fa4359", "span_id": "a477e8063f644093", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.342, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:07,452", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-80a59691feb54b418d1d0eedf037d21d", "trace_id": "77a0468240c3d6b629a46a4c66111998", "span_id": "4e10a97a71d95f6e"}
{"ts": "2026-07-14 10:37:07,461", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-80a59691feb54b418d1d0eedf037d21d", "trace_id": "77a0468240c3d6b629a46a4c66111998", "span_id": "4e10a97a71d95f6e"}
{"ts": "2026-07-14 10:37:07,469", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-80a59691feb54b418d1d0eedf037d21d", "trace_id": "77a0468240c3d6b629a46a4c66111998", "span_id": "4e10a97a71d95f6e"}
{"ts": "2026-07-14 10:37:07,469", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-80a59691feb54b418d1d0eedf037d21d", "trace_id": "77a0468240c3d6b629a46a4c66111998", "span_id": "4e10a97a71d95f6e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.83, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:09,863", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c7f5438839f344f2a8235a873ac6f7ef", "trace_id": "60a3506b17c3bded1ab35cd04d779cd8", "span_id": "4d3457bf5f8181aa", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:37:09,863", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c7f5438839f344f2a8235a873ac6f7ef", "trace_id": "60a3506b17c3bded1ab35cd04d779cd8", "span_id": "4d3457bf5f8181aa", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.239, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:37:17,452", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cd1c808356d4476a9f2ed65b574e0829", "trace_id": "416cce045f5d2642f613650c4dc01568", "span_id": "f4241e3556bf8a7e"}
{"ts": "2026-07-14 10:37:17,460", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cd1c808356d4476a9f2ed65b574e0829", "trace_id": "416cce045f5d2642f613650c4dc01568", "span_id": "f4241e3556bf8a7e"}
{"ts": "2026-07-14 10:37:17,468", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cd1c808356d4476a9f2ed65b574e0829", "trace_id": "416cce045f5d2642f613650c4dc01568", "span_id": "f4241e3556bf8a7e"}
{"ts": "2026-07-14 10:37:17,469", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-cd1c808356d4476a9f2ed65b574e0829", "trace_id": "416cce045f5d2642f613650c4dc01568", "span_id": "f4241e3556bf8a7e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.847, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:21,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9133deb15fa24786b3d4ded351b7c702", "trace_id": "16240086c4a024e03353a424c65354f3", "span_id": "d50056a051e0ffac", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.337, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:24,930", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d02884eed86b4fb197de34fc68074740", "trace_id": "57687ee407bfe1401b33a8aed1059d32", "span_id": "94d00bca38f0cd78", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:37:24,930", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d02884eed86b4fb197de34fc68074740", "trace_id": "57687ee407bfe1401b33a8aed1059d32", "span_id": "94d00bca38f0cd78", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.714, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:37:27,456", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fdcdf4315e0f4848a16295482d9dbd65", "trace_id": "480674b9bb19789512bc57394fcbdb04", "span_id": "717151dff0440779"}
{"ts": "2026-07-14 10:37:27,464", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fdcdf4315e0f4848a16295482d9dbd65", "trace_id": "480674b9bb19789512bc57394fcbdb04", "span_id": "717151dff0440779"}
{"ts": "2026-07-14 10:37:27,473", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-fdcdf4315e0f4848a16295482d9dbd65", "trace_id": "480674b9bb19789512bc57394fcbdb04", "span_id": "717151dff0440779"}
{"ts": "2026-07-14 10:37:27,473", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fdcdf4315e0f4848a16295482d9dbd65", "trace_id": "480674b9bb19789512bc57394fcbdb04", "span_id": "717151dff0440779", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.933, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:36,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1cc60f21c4f6447a833b4957101cfcc3", "trace_id": "e04a517952c3aeb3e26a9fd870af78b0", "span_id": "fdc089473629a753", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.297, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:37,452", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-554ed03ebdf046459177a8ab32e0270f", "trace_id": "edb68ea5d0472202311092fadbb818cf", "span_id": "d83482410155e583"}
{"ts": "2026-07-14 10:37:37,460", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-554ed03ebdf046459177a8ab32e0270f", "trace_id": "edb68ea5d0472202311092fadbb818cf", "span_id": "d83482410155e583"}
{"ts": "2026-07-14 10:37:37,469", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-554ed03ebdf046459177a8ab32e0270f", "trace_id": "edb68ea5d0472202311092fadbb818cf", "span_id": "d83482410155e583"}
{"ts": "2026-07-14 10:37:37,470", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-554ed03ebdf046459177a8ab32e0270f", "trace_id": "edb68ea5d0472202311092fadbb818cf", "span_id": "d83482410155e583", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.021, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:39,988", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-e2583f2c2eb04b82ad746dcf96f50c10", "trace_id": "3dd36c6f43dee45ecf91bcab8c882e9f", "span_id": "fcd72b0dfe31b306", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:37:39,988", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e2583f2c2eb04b82ad746dcf96f50c10", "trace_id": "3dd36c6f43dee45ecf91bcab8c882e9f", "span_id": "fcd72b0dfe31b306", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.171, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:37:47,458", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ed224d4bf0994bf9b227f9e602a7189c", "trace_id": "c447828e8d8d8b18b72d010ffb0931c0", "span_id": "60f2539606899349"}
{"ts": "2026-07-14 10:37:47,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ed224d4bf0994bf9b227f9e602a7189c", "trace_id": "c447828e8d8d8b18b72d010ffb0931c0", "span_id": "60f2539606899349"}
{"ts": "2026-07-14 10:37:47,475", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ed224d4bf0994bf9b227f9e602a7189c", "trace_id": "c447828e8d8d8b18b72d010ffb0931c0", "span_id": "60f2539606899349"}
{"ts": "2026-07-14 10:37:47,476", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ed224d4bf0994bf9b227f9e602a7189c", "trace_id": "c447828e8d8d8b18b72d010ffb0931c0", "span_id": "60f2539606899349", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.647, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:51,909", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8c1d9f0630bb435495e291d31d37f4a4", "trace_id": "c2b6338dc32505e446420fdb380d6df7", "span_id": "2fb61fed512e8b4f", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.107, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:37:55,049", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ebd1ba528c4c4845940531a9d13f6818", "trace_id": "c1ed6633ee51e8d9a271e69c9bd6d8bf", "span_id": "bf99ad44ba963ff4", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:37:55,049", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ebd1ba528c4c4845940531a9d13f6818", "trace_id": "c1ed6633ee51e8d9a271e69c9bd6d8bf", "span_id": "bf99ad44ba963ff4", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.39, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:37:57,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-48d7449c50b843609b72c94c9d0bb6ff", "trace_id": "892f1fcd7e0f09edcb2013a0ab19cd68", "span_id": "8566d9ea81f7cb9a"}
{"ts": "2026-07-14 10:37:57,460", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-48d7449c50b843609b72c94c9d0bb6ff", "trace_id": "892f1fcd7e0f09edcb2013a0ab19cd68", "span_id": "8566d9ea81f7cb9a"}
{"ts": "2026-07-14 10:37:57,468", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-48d7449c50b843609b72c94c9d0bb6ff", "trace_id": "892f1fcd7e0f09edcb2013a0ab19cd68", "span_id": "8566d9ea81f7cb9a"}
{"ts": "2026-07-14 10:37:57,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-48d7449c50b843609b72c94c9d0bb6ff", "trace_id": "892f1fcd7e0f09edcb2013a0ab19cd68", "span_id": "8566d9ea81f7cb9a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.88, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:06,914", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e9c4c1640a5d41a093f27d1170af40a5", "trace_id": "76177b430fb483ff3d08df928cd67b2b", "span_id": "1edf4aa952bc5823", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.207, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:07,450", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9f5ca91e17144cbc86c2b25d74c1d7d8", "trace_id": "47b7521d15503bf488c86eeade2981ce", "span_id": "4100f101b3410098"}
{"ts": "2026-07-14 10:38:07,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9f5ca91e17144cbc86c2b25d74c1d7d8", "trace_id": "47b7521d15503bf488c86eeade2981ce", "span_id": "4100f101b3410098"}
{"ts": "2026-07-14 10:38:07,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-9f5ca91e17144cbc86c2b25d74c1d7d8", "trace_id": "47b7521d15503bf488c86eeade2981ce", "span_id": "4100f101b3410098"}
{"ts": "2026-07-14 10:38:07,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-9f5ca91e17144cbc86c2b25d74c1d7d8", "trace_id": "47b7521d15503bf488c86eeade2981ce", "span_id": "4100f101b3410098", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.532, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:09,096", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-6611f8e84ebe43edb19cdbe6bfc9d5b7", "trace_id": "2b7a1038d36cc5212b1f55dc6cd6e9a2", "span_id": "1a0a4653f310f584", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:38:09,097", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-6611f8e84ebe43edb19cdbe6bfc9d5b7", "trace_id": "2b7a1038d36cc5212b1f55dc6cd6e9a2", "span_id": "1a0a4653f310f584", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.287, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:38:17,447", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-38381e18091f4449aac5729eadfbcbec", "trace_id": "72e0a05b4897000c13e990e468a6d15c", "span_id": "e6aba711cec497b4"}
{"ts": "2026-07-14 10:38:17,456", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-38381e18091f4449aac5729eadfbcbec", "trace_id": "72e0a05b4897000c13e990e468a6d15c", "span_id": "e6aba711cec497b4"}
{"ts": "2026-07-14 10:38:17,464", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-38381e18091f4449aac5729eadfbcbec", "trace_id": "72e0a05b4897000c13e990e468a6d15c", "span_id": "e6aba711cec497b4"}
{"ts": "2026-07-14 10:38:17,464", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-38381e18091f4449aac5729eadfbcbec", "trace_id": "72e0a05b4897000c13e990e468a6d15c", "span_id": "e6aba711cec497b4", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.824, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:21,915", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a38056052d2f4e978d71d36c1c571a05", "trace_id": "4ea026a307a26bfeda961a4b3b475c5d", "span_id": "fa716dd669c2235d", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.23, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:24,154", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-cd5392be3a5d4b5e902bb30e38931882", "trace_id": "239d7ea6035f51d8b27fffc73b8fd471", "span_id": "6ea1870ab8c44673", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:38:24,155", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-cd5392be3a5d4b5e902bb30e38931882", "trace_id": "239d7ea6035f51d8b27fffc73b8fd471", "span_id": "6ea1870ab8c44673", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.046, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:38:27,450", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-caa07ce6c8f34b37b38388a4d80973cc", "trace_id": "1fcc47602e2d7c44320794d3a21d1674", "span_id": "75ebea24f1657636"}
{"ts": "2026-07-14 10:38:27,458", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-caa07ce6c8f34b37b38388a4d80973cc", "trace_id": "1fcc47602e2d7c44320794d3a21d1674", "span_id": "75ebea24f1657636"}
{"ts": "2026-07-14 10:38:27,466", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-caa07ce6c8f34b37b38388a4d80973cc", "trace_id": "1fcc47602e2d7c44320794d3a21d1674", "span_id": "75ebea24f1657636"}
{"ts": "2026-07-14 10:38:27,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-caa07ce6c8f34b37b38388a4d80973cc", "trace_id": "1fcc47602e2d7c44320794d3a21d1674", "span_id": "75ebea24f1657636", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.895, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:36,916", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-6caf82b3e82d496da585a543b0a9fc7c", "trace_id": "ec99dfcb328c0a59254061e17b0b77b1", "span_id": "712a46247570188c", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.217, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:37,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-76f8e5c7651b4be6ac0909af73ddac29", "trace_id": "0e0f3998910bb20d7b5fc7edfb9b4c93", "span_id": "deee9dba028a9236"}
{"ts": "2026-07-14 10:38:37,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-76f8e5c7651b4be6ac0909af73ddac29", "trace_id": "0e0f3998910bb20d7b5fc7edfb9b4c93", "span_id": "deee9dba028a9236"}
{"ts": "2026-07-14 10:38:37,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-76f8e5c7651b4be6ac0909af73ddac29", "trace_id": "0e0f3998910bb20d7b5fc7edfb9b4c93", "span_id": "deee9dba028a9236"}
{"ts": "2026-07-14 10:38:37,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-76f8e5c7651b4be6ac0909af73ddac29", "trace_id": "0e0f3998910bb20d7b5fc7edfb9b4c93", "span_id": "deee9dba028a9236", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.75, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:39,200", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-3e3e43c6be774798b116914f03750a61", "trace_id": "66293e67f1a149601c53619ae06db9ad", "span_id": "65bbbb43db34854f", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:38:39,200", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3e3e43c6be774798b116914f03750a61", "trace_id": "66293e67f1a149601c53619ae06db9ad", "span_id": "65bbbb43db34854f", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.001, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:38:47,450", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-8e3f445759744f9e8ee0bb9ddc824585", "trace_id": "5666c17e381dd3ce585dd1ec6b418339", "span_id": "aa3f847b995c2ff6"}
{"ts": "2026-07-14 10:38:47,458", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-8e3f445759744f9e8ee0bb9ddc824585", "trace_id": "5666c17e381dd3ce585dd1ec6b418339", "span_id": "aa3f847b995c2ff6"}
{"ts": "2026-07-14 10:38:47,466", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-8e3f445759744f9e8ee0bb9ddc824585", "trace_id": "5666c17e381dd3ce585dd1ec6b418339", "span_id": "aa3f847b995c2ff6"}
{"ts": "2026-07-14 10:38:47,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8e3f445759744f9e8ee0bb9ddc824585", "trace_id": "5666c17e381dd3ce585dd1ec6b418339", "span_id": "aa3f847b995c2ff6", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.407, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:51,919", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2e8c7651d44f4cf4b11021b0e8ea5128", "trace_id": "8149d761a86a821ca3de8d6c7029079e", "span_id": "065787e60ecf1d2a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.098, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:38:54,255", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-eb626157d4b64cb69b37984122b43d6e", "trace_id": "08e96b2e1ad8d8aa6deaf3aa772dcebc", "span_id": "a81cb3ab85e05133", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:38:54,255", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-eb626157d4b64cb69b37984122b43d6e", "trace_id": "08e96b2e1ad8d8aa6deaf3aa772dcebc", "span_id": "a81cb3ab85e05133", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.81, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:38:54,697", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-db4d799471604a68b53f020f3bdacb89", "trace_id": "a1b034edb14d85c904e60262f2aac8fc", "span_id": "e4a653580dc2ba4c", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:38:54,697", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-db4d799471604a68b53f020f3bdacb89", "trace_id": "a1b034edb14d85c904e60262f2aac8fc", "span_id": "e4a653580dc2ba4c", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.001, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:38:57,449", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0f584a70c25f48bdad27df51c3652a88", "trace_id": "aa6452c3b3eddf5164c92a833b58afa1", "span_id": "54aa0d1143ee6830"}
{"ts": "2026-07-14 10:38:57,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0f584a70c25f48bdad27df51c3652a88", "trace_id": "aa6452c3b3eddf5164c92a833b58afa1", "span_id": "54aa0d1143ee6830"}
{"ts": "2026-07-14 10:38:57,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0f584a70c25f48bdad27df51c3652a88", "trace_id": "aa6452c3b3eddf5164c92a833b58afa1", "span_id": "54aa0d1143ee6830"}
{"ts": "2026-07-14 10:38:57,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0f584a70c25f48bdad27df51c3652a88", "trace_id": "aa6452c3b3eddf5164c92a833b58afa1", "span_id": "54aa0d1143ee6830", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.688, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:06,914", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ee27699d722a40668aa5d15b01216b51", "trace_id": "113a8facad7554ad0c57524b3db60ab3", "span_id": "1b6306f377c3ee69", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.211, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:07,450", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-352e3a60da534cb2aeae25cbd08a6f3a", "trace_id": "395259f09d420dc4610ce0c2e9a77d0a", "span_id": "17d8e6dfd693e162"}
{"ts": "2026-07-14 10:39:07,457", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-352e3a60da534cb2aeae25cbd08a6f3a", "trace_id": "395259f09d420dc4610ce0c2e9a77d0a", "span_id": "17d8e6dfd693e162"}
{"ts": "2026-07-14 10:39:07,466", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-352e3a60da534cb2aeae25cbd08a6f3a", "trace_id": "395259f09d420dc4610ce0c2e9a77d0a", "span_id": "17d8e6dfd693e162"}
{"ts": "2026-07-14 10:39:07,466", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-352e3a60da534cb2aeae25cbd08a6f3a", "trace_id": "395259f09d420dc4610ce0c2e9a77d0a", "span_id": "17d8e6dfd693e162", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.656, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:09,925", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-8a1ff0b358e949809fcd74ee3facf7fa", "trace_id": "0888b93d620b9e72e449a5ef30c37c56", "span_id": "b374ad7a12db1afa", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 10:39:09,925", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8a1ff0b358e949809fcd74ee3facf7fa", "trace_id": "0888b93d620b9e72e449a5ef30c37c56", "span_id": "b374ad7a12db1afa", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.587, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 10:39:17,450", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e6fa28a2617a444783a0d6fbda3083fe", "trace_id": "e6880c8e1c5c93734757fbeb4753aa46", "span_id": "afa325b065d84710"}
{"ts": "2026-07-14 10:39:17,459", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e6fa28a2617a444783a0d6fbda3083fe", "trace_id": "e6880c8e1c5c93734757fbeb4753aa46", "span_id": "afa325b065d84710"}
{"ts": "2026-07-14 10:39:17,467", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e6fa28a2617a444783a0d6fbda3083fe", "trace_id": "e6880c8e1c5c93734757fbeb4753aa46", "span_id": "afa325b065d84710"}
{"ts": "2026-07-14 10:39:17,467", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e6fa28a2617a444783a0d6fbda3083fe", "trace_id": "e6880c8e1c5c93734757fbeb4753aa46", "span_id": "afa325b065d84710", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.322, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:21,913", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8bef134bf7a3404d8257639dd8c04faa", "trace_id": "85218afc7b1a3f0b486d3026571c743a", "span_id": "3506f3148ad57ba2", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.183, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:27,451", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-be25452cfa7b47b29a72ad7e8bce03eb", "trace_id": "4efb4edbf25cb6710d930691d534e350", "span_id": "cfa478174863aa1d"}
{"ts": "2026-07-14 10:39:27,460", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-be25452cfa7b47b29a72ad7e8bce03eb", "trace_id": "4efb4edbf25cb6710d930691d534e350", "span_id": "cfa478174863aa1d"}
{"ts": "2026-07-14 10:39:27,468", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-be25452cfa7b47b29a72ad7e8bce03eb", "trace_id": "4efb4edbf25cb6710d930691d534e350", "span_id": "cfa478174863aa1d"}
{"ts": "2026-07-14 10:39:27,468", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-be25452cfa7b47b29a72ad7e8bce03eb", "trace_id": "4efb4edbf25cb6710d930691d534e350", "span_id": "cfa478174863aa1d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.456, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:36,910", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-37c52720b833453ea71d76f7257b3858", "trace_id": "89146fbca7b03e96c78c04daf6cffd18", "span_id": "44436ec61ce50c02", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.128, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:37,446", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-36c8219daf6a4344ba321b7141c7cba7", "trace_id": "f16d915874556f671fd637ebb2330e66", "span_id": "79dfeb6b4bd33c84"}
{"ts": "2026-07-14 10:39:37,455", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-36c8219daf6a4344ba321b7141c7cba7", "trace_id": "f16d915874556f671fd637ebb2330e66", "span_id": "79dfeb6b4bd33c84"}
{"ts": "2026-07-14 10:39:37,462", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-36c8219daf6a4344ba321b7141c7cba7", "trace_id": "f16d915874556f671fd637ebb2330e66", "span_id": "79dfeb6b4bd33c84"}
{"ts": "2026-07-14 10:39:37,463", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-36c8219daf6a4344ba321b7141c7cba7", "trace_id": "f16d915874556f671fd637ebb2330e66", "span_id": "79dfeb6b4bd33c84", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.122, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:47,449", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7195b8954c07411fa1a27bb69d7210f8", "trace_id": "add2867021c3a24e6c3bb9c5df870604", "span_id": "c3408bc21b931bf3"}
{"ts": "2026-07-14 10:39:47,458", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7195b8954c07411fa1a27bb69d7210f8", "trace_id": "add2867021c3a24e6c3bb9c5df870604", "span_id": "c3408bc21b931bf3"}
{"ts": "2026-07-14 10:39:47,465", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-7195b8954c07411fa1a27bb69d7210f8", "trace_id": "add2867021c3a24e6c3bb9c5df870604", "span_id": "c3408bc21b931bf3"}
{"ts": "2026-07-14 10:39:47,466", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7195b8954c07411fa1a27bb69d7210f8", "trace_id": "add2867021c3a24e6c3bb9c5df870604", "span_id": "c3408bc21b931bf3", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.904, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 10:39:49,708", "level": "WARNING", "logger": "cognic_agentos.portal.rbac.enforcement", "message": "portal.rbac.scope_not_held", "request_id": "portal-req-fc91ac4f1f5249e0aa92496665af6948", "trace_id": "6980791c5887cc4579d7545f6d3a8623", "span_id": "e3d3567625f56434", "reason": "scope_not_held", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#5bf86cbe-115d-550a-94ef-1742179f0c33", "tenant_id": "proof-m85c", "http_status": 403, "required_scope": "conversation.read"}
{"ts": "2026-07-14 10:39:49,709", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fc91ac4f1f5249e0aa92496665af6948", "trace_id": "6980791c5887cc4579d7545f6d3a8623", "span_id": "e3d3567625f56434", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 403, "duration_ms": 0.5, "client_addr": "10.244.0.34"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T11:30:04Z)

- Failed step: `BAR A XSS — the hostile markup was NOT present as rendered text (vacuous pass: nothing to escape?)`
- last API response (HTTP 200):
```json
{"tools":[{"name":"probe_write","title":null,"description":"Append a per-call nonce to the proof-local invocation ledger and return the nonce plus the ledger line count. Business-side-effect-free: the ledger is proof instrumentation for the ADR-014 four-eyes approval proof (the independent observer that makes 'zero execution' provable), not a business write.","inputSchema":{"properties":{"nonce":{"title":"Nonce","type":"string"}},"required":["nonce"],"title":"probe_writeArguments","type":"object"},"outputSchema":{"additionalProperties":true,"title":"probe_writeDictOutput","type":"object"},"icons":null,"annotations":null,"_meta":null,"execution":null}]}
```
- conversation.% chain rows (tail 10 — digest-only):
```
conversation.created|{"agent_id": "bank-analyst", "conversation_id": "568b6c12-3306-47e2-863e-39d09b3f371e", "created_at": "2026-07-14T11:29:52.635075+00:00", "creator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- conversations operational records (tail 6 — no plaintext):
```
568b6c12-3306-47e2-863e-39d09b3f371e | active | turns=0 | tokens=0 | in_progress=true
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
agent.run.started|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "max_steps": 6, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prior_context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "prior_context_turns": 0, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "run_id": "agent-run-4bafcb682ecb4bce8fb952b72eba051c", "token_budget": 60000, "wall_clock_s": 300.0}
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
<none>
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
<none>
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m11:28:20 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m11:28:20 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#            'This product would be better if...'             #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:37254 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:60366 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51116 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:40210 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:55318 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54792 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39868 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:41318 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47246 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:50978 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:60666 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
<none>
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"ef505353afb36b2e0b7f62a0e7d160658d915679dba75c43e789e148641f1899","refusal_reason":null,"registered_at":"2026-07-14T11:29:27.896548+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9777623c207320f00efb68762079aa9c3bdf4499a340dd594f2828eb285b893e","refusal_reason":null,"registered_at":"2026-07-14T11:29:28.097353+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T11:29:28.290809+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T11:29:28.492780+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T11:29:28.691699+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T11:29:28.891760+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T11:29:29.090628+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T11:29:29.283656+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T11:29:29.490136+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Trace ID       : 8963ac053ef0b1ee21cbeacc70cddf2e
    Parent ID      : 5ddbbd3ea0e04151
    ID             : 4a1d1df2620da585
    Name           : GET /api/v1/conversations/{conversation_id}/transcript http send
    Kind           : Internal
    Start time     : 2026-07-14 11:29:52.659270721 +0000 UTC
    End time       : 2026-07-14 11:29:52.659276888 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #31
    Trace ID       : 8963ac053ef0b1ee21cbeacc70cddf2e
    Parent ID      : 5ddbbd3ea0e04151
    ID             : 483bbc2b0383e366
    Name           : GET /api/v1/conversations/{conversation_id}/transcript http send
    Kind           : Internal
    Start time     : 2026-07-14 11:29:52.65930418 +0000 UTC
    End time       : 2026-07-14 11:29:52.659309388 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #32
    Trace ID       : 8963ac053ef0b1ee21cbeacc70cddf2e
    Parent ID      :
    ID             : 5ddbbd3ea0e04151
    Name           : GET /api/v1/conversations/{conversation_id}/transcript
    Kind           : Server
    Start time     : 2026-07-14 11:29:52.654469346 +0000 UTC
    End time       : 2026-07-14 11:29:52.659322471 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/conversations/568b6c12-3306-47e2-863e-39d09b3f371e/transcript)
     -> http.url: Str(https://rel-agentos:8443/api/v1/conversations/568b6c12-3306-47e2-863e-39d09b3f371e/transcript)
     -> http.method: Str(GET)
     -> http.server_name: Str(rel-agentos:8443)
     -> http.user_agent: Str(python-httpx/0.28.1)
     -> net.peer.ip: Str(10.244.0.30)
     -> net.peer.port: Int(52696)
     -> http.route: Str(/api/v1/conversations/{conversation_id}/transcript)
     -> http.status_code: Int(200)
Span #33
    Trace ID       : e0ebdbe75afe6ec68b4c965f39aea6d1
    Parent ID      : 13d870c9c44f730d
    ID             : cd200fb2c05a2721
    Name           : POST /api/v1/conversations/{conversation_id}/turns http receive
    Kind           : Internal
    Start time     : 2026-07-14 11:29:52.727096846 +0000 UTC
    End time       : 2026-07-14 11:29:52.72711093 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.request)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
Defaulted container "agentos" out of: agentos, broker-share-perms (init)
INFO:     Started server process [1]
INFO:     Waiting for application startup.
{"ts": "2026-07-14 11:29:27,165", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333 \"HTTP/1.1 200 OK\"", "request_id": null, "trace_id": null, "span_id": null}
{"ts": "2026-07-14 11:29:29,938", "level": "INFO", "logger": "cognic_agentos.portal.api.app", "message": "sandbox.reaper.disabled", "request_id": null, "trace_id": null, "span_id": null, "remediation": "set sandbox_reaper_enabled=true on EXACTLY ONE instance to run the resumable-session retention sweep (single-instance posture per spec \u00a713; Sprint 10.5 adds leader election)"}
INFO:     Application startup complete.
INFO:     Uvicorn running on https://0.0.0.0:8443 (Press CTRL+C to quit)
{"ts": "2026-07-14 11:29:32,010", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2b2f4758b80a43ada899bd11b2fc9d79", "trace_id": "12ff96d6b9efdee23a9fe472dd8e7fcf", "span_id": "479245647a4e0b4e", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.879, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:29:32,534", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f702476646d14b6cb045e2ada250bf25", "trace_id": "7987177681165ade5210d0b6eed50c34", "span_id": "91f09ee6ca4f3d09"}
{"ts": "2026-07-14 11:29:32,543", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f702476646d14b6cb045e2ada250bf25", "trace_id": "7987177681165ade5210d0b6eed50c34", "span_id": "91f09ee6ca4f3d09"}
{"ts": "2026-07-14 11:29:32,550", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f702476646d14b6cb045e2ada250bf25", "trace_id": "7987177681165ade5210d0b6eed50c34", "span_id": "91f09ee6ca4f3d09"}
{"ts": "2026-07-14 11:29:32,551", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f702476646d14b6cb045e2ada250bf25", "trace_id": "7987177681165ade5210d0b6eed50c34", "span_id": "91f09ee6ca4f3d09", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.784, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:29:33,640", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-2f6fdd2644bf45438faede7db33d8547", "trace_id": "8338d7f2dfeccb6dc079c87f978906b7", "span_id": "4785334e2e3a4bdb", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.119, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 11:29:33,694", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 401 Unauthorized\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,697", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/.well-known/oauth-protected-resource/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,700", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://192.88.99.9:9000/.well-known/oauth-authorization-server \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,701", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://192.88.99.9:9000/token \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,877", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,877", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Received session ID: b1da72585a0c4a7c853fc0d6ef7fa788", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,878", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "Negotiated protocol version: 2025-11-25", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,880", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 202 Accepted\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,881", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,882", "level": "INFO", "logger": "httpx", "message": "HTTP Request: POST http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,884", "level": "INFO", "logger": "httpx", "message": "HTTP Request: DELETE http://10.96.0.52:8766/mcp \"HTTP/1.1 200 OK\"", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,884", "level": "INFO", "logger": "mcp.client.streamable_http", "message": "GET stream disconnected, reconnecting in 1000ms...", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2"}
{"ts": "2026-07-14 11:29:33,884", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-99ac9ee67b264ee7b135afdd72398d7f", "trace_id": "32519a1f967f567ba8fde647b586c25f", "span_id": "d068b1234d65afb2", "http_method": "GET", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 197.531, "client_addr": "127.0.0.1"}
{"ts": "2026-07-14 11:29:37,005", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d121034eb7ec478d90c6e28e43e65b98", "trace_id": "101ed20472e9a74b6e7ee2d4656a2b83", "span_id": "bf159a996c213917", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.111, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:29:37,266", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c05a9fa8901740c9a1e113f7f7630a63", "trace_id": "1f865b1957ae27fcf37a712f2abb5305", "span_id": "a78b2d0b7b848bc0", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:37,266", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c05a9fa8901740c9a1e113f7f7630a63", "trace_id": "1f865b1957ae27fcf37a712f2abb5305", "span_id": "a78b2d0b7b848bc0", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 5.375, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 11:29:40,745", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ca0b6428738e42c09a2722769cb90854", "trace_id": "eeaddf52198a8820f7a2cc1409b3dff2", "span_id": "bb15459141badf3d", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:40,745", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ca0b6428738e42c09a2722769cb90854", "trace_id": "eeaddf52198a8820f7a2cc1409b3dff2", "span_id": "bb15459141badf3d", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.448, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 11:29:42,428", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-089243162a5b4618abe01bbb388fa578", "trace_id": "533f9fdc102e6d21a881b3b8722181b9", "span_id": "7c4cd55a15e1ece4", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:42,428", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-089243162a5b4618abe01bbb388fa578", "trace_id": "533f9fdc102e6d21a881b3b8722181b9", "span_id": "7c4cd55a15e1ece4", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.946, "client_addr": "10.244.0.25"}
{"ts": "2026-07-14 11:29:42,534", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4666a4937d67490cb65900ef7578f09e", "trace_id": "eb432729594d1a5689583fabe7732681", "span_id": "e35fc07ef85cccbe"}
{"ts": "2026-07-14 11:29:42,543", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4666a4937d67490cb65900ef7578f09e", "trace_id": "eb432729594d1a5689583fabe7732681", "span_id": "e35fc07ef85cccbe"}
{"ts": "2026-07-14 11:29:42,553", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-4666a4937d67490cb65900ef7578f09e", "trace_id": "eb432729594d1a5689583fabe7732681", "span_id": "e35fc07ef85cccbe"}
{"ts": "2026-07-14 11:29:42,554", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4666a4937d67490cb65900ef7578f09e", "trace_id": "eb432729594d1a5689583fabe7732681", "span_id": "e35fc07ef85cccbe", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.012, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:29:51,264", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-079714ad9ba745889567833d3bd97e53", "trace_id": "da81a393496d7af18dcf5c4383811a2f", "span_id": "fa6e4076856e8934", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:51,265", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-079714ad9ba745889567833d3bd97e53", "trace_id": "da81a393496d7af18dcf5c4383811a2f", "span_id": "fa6e4076856e8934", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.064, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:29:51,885", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-e9810318b43d4b12ba4ed71bace54d24", "trace_id": "67eadd87b83cff6d4ecf1e56abb1fdb4", "span_id": "140e01c092d0df79", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:51,885", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e9810318b43d4b12ba4ed71bace54d24", "trace_id": "67eadd87b83cff6d4ecf1e56abb1fdb4", "span_id": "140e01c092d0df79", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.718, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:29:52,008", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-dd4bafa38e93463d97bf84b6dd33cc39", "trace_id": "511ed00c7c53c5a24683da2d9e78aa2d", "span_id": "83e339614100ece7", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.105, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:29:52,513", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-b25c9f6630b24792b9c392f397e65217", "trace_id": "b6d30d1ac39343a74d00a9037850086a", "span_id": "c0e4a35906a85c93", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:52,514", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-b25c9f6630b24792b9c392f397e65217", "trace_id": "b6d30d1ac39343a74d00a9037850086a", "span_id": "c0e4a35906a85c93", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.566, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:29:52,535", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-52f46e52c00847e8971d72699f026941", "trace_id": "86eb002b484b89596d49ab2c70357f3a", "span_id": "268fde49d9fadf1e"}
{"ts": "2026-07-14 11:29:52,545", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-52f46e52c00847e8971d72699f026941", "trace_id": "86eb002b484b89596d49ab2c70357f3a", "span_id": "268fde49d9fadf1e"}
{"ts": "2026-07-14 11:29:52,554", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-52f46e52c00847e8971d72699f026941", "trace_id": "86eb002b484b89596d49ab2c70357f3a", "span_id": "268fde49d9fadf1e"}
{"ts": "2026-07-14 11:29:52,554", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-52f46e52c00847e8971d72699f026941", "trace_id": "86eb002b484b89596d49ab2c70357f3a", "span_id": "268fde49d9fadf1e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.625, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:29:52,640", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c081f1fda9f742d0a770aacbdbe7a5e8", "trace_id": "9b96f7b84316c803df4b0015e76a1948", "span_id": "6b376b109a318121", "http_method": "POST", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 201, "duration_ms": 7.408, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:29:52,652", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-5b50ced6d663484696811da17b05917d", "trace_id": "67f454e642c9f944a890f985aa93e7c5", "span_id": "b0f2466140c9be1d", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:52,652", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5b50ced6d663484696811da17b05917d", "trace_id": "67f454e642c9f944a890f985aa93e7c5", "span_id": "b0f2466140c9be1d", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.553, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:29:52,658", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-f0b7c8f615654f8f82712d846ef67d0f", "trace_id": "8963ac053ef0b1ee21cbeacc70cddf2e", "span_id": "5ddbbd3ea0e04151", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "568b6c12-3306-47e2-863e-39d09b3f371e", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:29:52,658", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f0b7c8f615654f8f82712d846ef67d0f", "trace_id": "8963ac053ef0b1ee21cbeacc70cddf2e", "span_id": "5ddbbd3ea0e04151", "http_method": "GET", "http_path": "/api/v1/conversations/568b6c12-3306-47e2-863e-39d09b3f371e/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 4.294, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:30:02,533", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-db1261623b9743f2bf06f577017c6853", "trace_id": "ddcad0c039a7c29163f585277b5bfdad", "span_id": "e9434c83d6cc959c"}
{"ts": "2026-07-14 11:30:02,540", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-db1261623b9743f2bf06f577017c6853", "trace_id": "ddcad0c039a7c29163f585277b5bfdad", "span_id": "e9434c83d6cc959c"}
{"ts": "2026-07-14 11:30:02,548", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-db1261623b9743f2bf06f577017c6853", "trace_id": "ddcad0c039a7c29163f585277b5bfdad", "span_id": "e9434c83d6cc959c"}
{"ts": "2026-07-14 11:30:02,548", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-db1261623b9743f2bf06f577017c6853", "trace_id": "ddcad0c039a7c29163f585277b5bfdad", "span_id": "e9434c83d6cc959c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 17.35, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 11:30:03,286", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-24689f2e2697457e9007ece31f47dcad", "trace_id": "96ba4380b7d9cb7ddbdd85b569679009", "span_id": "c6e848fca36ea80c", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:30:03,286", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-24689f2e2697457e9007ece31f47dcad", "trace_id": "96ba4380b7d9cb7ddbdd85b569679009", "span_id": "c6e848fca36ea80c", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 3.611, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:30:03,296", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-820f6d51a1bf4a74b10afbf473f344d3", "trace_id": "0b5601a4f2205f0e31ade35e19fb76a9", "span_id": "24f4eb945f548407", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "568b6c12-3306-47e2-863e-39d09b3f371e", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:30:03,296", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-820f6d51a1bf4a74b10afbf473f344d3", "trace_id": "0b5601a4f2205f0e31ade35e19fb76a9", "span_id": "24f4eb945f548407", "http_method": "GET", "http_path": "/api/v1/conversations/568b6c12-3306-47e2-863e-39d09b3f371e/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 5.25, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 11:30:03,382", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.transcript", "request_id": "portal-req-93c3fc0a00fc430fad354eae265ec029", "trace_id": "65b2bd128fe35f250e1ab6c209723456", "span_id": "7c9705f9d33e51cc", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": "568b6c12-3306-47e2-863e-39d09b3f371e", "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 11:30:03,382", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-93c3fc0a00fc430fad354eae265ec029", "trace_id": "65b2bd128fe35f250e1ab6c209723456", "span_id": "7c9705f9d33e51cc", "http_method": "GET", "http_path": "/api/v1/conversations/568b6c12-3306-47e2-863e-39d09b3f371e/transcript", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.206, "client_addr": "10.244.0.30"}
```

## Proof M8.5 slice — FAILURE (2026-07-14T12:43:56Z)

- Failed step: `mint_probe_request(amir): the 202 carried no approval_request_id (body: {"detail":{"reason":"tool_approval_pending","approval_request_id":"7892230e-7b96-41e6-b14c-271a245b3936"}})`
- last API response (HTTP 202):
```json
{"detail":{"reason":"tool_approval_pending","approval_request_id":"7892230e-7b96-41e6-b14c-271a245b3936"}}
```
- conversation.% chain rows (tail 10 — digest-only):
```
conversation.turn_completed|{"agent_run_id": "agent-run-52f1df7ea6214bc99ebc74e3ab722448", "answer_bytes": 44, "answer_sha256": "401a711e087e2b175158e90c32a556eeb88a20fe76c6ca3de9e48b74d349861c", "completion_tokens": 11, "conversation_id": "ac56ec65-2ced-4319-828b-835fbd01395d", "prompt_tokens": 970, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "seq": 1, "turn_id": "d27ae732-443f-4848-abdf-7a6ac2da5926", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
conversation.created|{"agent_id": "bank-analyst", "conversation_id": "ac56ec65-2ced-4319-828b-835fbd01395d", "created_at": "2026-07-14T12:38:44.147117+00:00", "creator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- conversations operational records (tail 6 — no plaintext):
```
ac56ec65-2ced-4319-828b-835fbd01395d | active | turns=1 | tokens=981 | in_progress=false
```
- agent / dispatch / gateway reason markers:
```
conversation_id
```
- agent.run.% run rows (tail 10 — started/terminal, digest-only):
```
agent.run.completed|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "answer_bytes": 44, "answer_sha256": "401a711e087e2b175158e90c32a556eeb88a20fe76c6ca3de9e48b74d349861c", "completion_tokens_total": 11, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prompt_tokens_total": 970, "run_id": "agent-run-52f1df7ea6214bc99ebc74e3ab722448", "steps_used": 1}
agent.run.started|{"actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "agent_id": "bank-analyst", "max_steps": 6, "originator_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "prior_context_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "prior_context_turns": 0, "question_bytes": 125, "question_sha256": "135ad09bdd50627a50cbb1b7139aec88d7cf331a09249df8e67f76c5f2414eaf", "run_id": "agent-run-52f1df7ea6214bc99ebc74e3ab722448", "token_budget": 60000, "wall_clock_s": 300.0}
```
- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):
```
<none>
```
- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):
```
audit.tool_invocation_refused|{"approval_request_id": "7892230e-7b96-41e6-b14c-271a245b3936", "as_issuer": null, "client_id": null, "declared_risk_tier": "high_risk_custom", "flow": "require_4_eyes", "mcp_session_id": null, "pack_id": "cognic-tool-approval-probe", "pack_signature_digest": "cbc650f36bff23f4d81dcef9c1e8bcb32d94562fb693eba247e7b74e7aa092e7", "refusal_reason": "tool_approval_pending", "resource_indicator": null, "scopes": null, "tool_name": "probe_write"}
```
- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):
```
agent-run-52f1df7ea6214bc99ebc74e3ab722448-s0 | cognic-tier1-proof-m85c | openai/gpt-4o | external=true | resolved | ok
```
- litellm router logs (tail 120 — finding #7 upstream-reason surface):
```
INFO:     Started server process [1]
INFO:     Waiting for application startup.

   ██╗     ██╗████████╗███████╗██╗     ██╗     ███╗   ███╗
   ██║     ██║╚══██╔══╝██╔════╝██║     ██║     ████╗ ████║
   ██║     ██║   ██║   █████╗  ██║     ██║     ██╔████╔██║
   ██║     ██║   ██║   ██╔══╝  ██║     ██║     ██║╚██╔╝██║
   ███████╗██║   ██║   ███████╗███████╗███████╗██║ ╚═╝ ██║
   ╚══════╝╚═╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝

[92m12:37:17 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=28b6d2983a6f399677da597ca6fb94e53da2c35b3f6d0b03ddddeb24d8b9f6a8 not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
[92m12:37:17 - LiteLLM:WARNING[0m: utils.py:2730 - register_model: model=c90f9f582b805612e00a15941fb336b8fd2f4ca2c308c949de41ac764c32e84a not in built-in cost map and no prefix/region variant matched; cache cost fields will default to 0. To track cache cost, add cache_creation_input_token_cost and cache_read_input_token_cost to model_info
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:4000 (Press CTRL+C to quit)

[1;37m#------------------------------------------------------------#[0m
[1;37m#                                                            #[0m
[1;37m#            'This product would be better if...'             #[0m
[1;37m#        https://github.com/BerriAI/litellm/issues/new        #[0m
[1;37m#                                                            #[0m
[1;37m#------------------------------------------------------------#[0m

 Thank you for using LiteLLM! - Krrish & Ishaan



[1;31mGive Feedback / Get Help: https://github.com/BerriAI/litellm/issues/new[0m


[32mLiteLLM: Proxy initialized with Config, Set models:[0m
[32m    cognic-tier1-proof-m85c[0m
[32m    cognic-tier2-proof-m85c[0m
INFO:     10.244.0.1:58948 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:56260 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53700 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:59616 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:48828 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39862 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47670 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36796 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46606 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.29:56484 - "POST /chat/completions HTTP/1.1" 200 OK
INFO:     10.244.0.1:51556 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47046 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:38390 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:59850 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:42276 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:49158 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:52936 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36956 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54326 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35970 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:34440 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:42854 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:46368 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51960 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:36478 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:52766 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:33986 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:37294 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:54398 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:39342 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:42336 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:35130 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:52830 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:40910 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:44208 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:51376 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:34666 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:57364 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:47508 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53822 - "GET /health/liveliness HTTP/1.1" 200 OK
INFO:     10.244.0.1:53322 - "GET /health/liveliness HTTP/1.1" 200 OK
```
- memory.write rows (tail 4 — the task-tier digest axis):
```
{"approval_verified": false, "block_kind": null, "data_classes": ["operational_telemetry"], "purpose": "agent_run_notes", "record_id": "a2bd315e-683a-4d08-85fd-3ac638bccf8c", "redacted_value_digest": "e2a129e32081fd2c1afb58699d69f24c64a57cc62f3e2e8e9872308ecea5b7a0", "retention_until": null, "subject_ref": "human:https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "tier": "task", "actor_id": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660"}
```
- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):
```json
{"plugins":[{"kind":"tools","name":"oracle_schema","pack_id":"cognic-tool-oracle-schema","version":"0.3.0","status":"registered","attestation_grade":"partial","signature_digest":"9fa7a3bf2c953209b33560b1f0e471ad64a6d467c75e50fa942f00f057ef7714","refusal_reason":null,"registered_at":"2026-07-14T12:38:18.280815+00:00","discovery_status":"unprobed"},{"kind":"tools","name":"approval_probe","pack_id":"cognic-tool-approval-probe","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cbc650f36bff23f4d81dcef9c1e8bcb32d94562fb693eba247e7b74e7aa092e7","refusal_reason":null,"registered_at":"2026-07-14T12:38:18.485527+00:00","discovery_status":"auth_ready"},{"kind":"agents","name":"bank-analyst","pack_id":"cognic-agent-bank-analyst","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"5b8573dbdcb0f1216779325ea514223a89862714a276f205df6c112d54565a9f","refusal_reason":null,"registered_at":"2026-07-14T12:38:18.783358+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"explode_schema_guard","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T12:38:18.990476+00:00","discovery_status":"unprobed"},{"kind":"hooks","name":"refuse_forbidden_schema_arg","pack_id":"cognic-hook-schema-guard","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"76f272a908860edb5cc384445517387755b47b340ebae0e34912af16b6efbb78","refusal_reason":null,"registered_at":"2026-07-14T12:38:19.194373+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-customer-data","pack_id":"cognic-skill-customer-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"a7dbffca8df5535a8f59a6302dc4e666d4b332adea726a780f7d3d13e3a4d94a","refusal_reason":null,"registered_at":"2026-07-14T12:38:19.395202+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-atm-recon","pack_id":"cognic-skill-atm-recon","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"cb77ad1af0b67440d053d8c670991c85371bad50ef6a3f037803848fcdb6534b","refusal_reason":null,"registered_at":"2026-07-14T12:38:19.593697+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-financial-data","pack_id":"cognic-skill-financial-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"e62d610817955999f3924eb28a5da84c3a9b913698e09cf802318ce3645102f2","refusal_reason":null,"registered_at":"2026-07-14T12:38:19.800451+00:00","discovery_status":"unprobed"},{"kind":"skills","name":"cognic-skill-cards-data","pack_id":"cognic-skill-cards-data","version":"0.1.0","status":"registered","attestation_grade":"partial","signature_digest":"9d72f8048def867889d3014b28ca9142ee96098e36cd9bcf9a485fa58b1201b5","refusal_reason":null,"registered_at":"2026-07-14T12:38:20.001050+00:00","discovery_status":"unprobed"}],"hosted_skills":[{"skill_id":"customer-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"atm-recon","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"financial-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"},{"skill_id":"cards-data","entry_point":null,"declared_tools":[],"runtime_image":null,"pack_version":"0.1.0"}],"hosted_agents":[{"agent_id":"bank-analyst","requested_skills":["customer-data","financial-data","cards-data"],"requested_tools":["cognic-tool-oracle-schema/run_readonly_query"],"max_steps":6,"risk_tier":"customer_data_read","pack_version":"0.1.0"}],"summary":{"total_discovered":9,"registered":9,"refused_at_registration":0,"by_grade":{"full":0,"partial":9},"by_discovery_status":{"unprobed":8,"auth_ready":1,"refused":0,"unreachable":0}}}
```
- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):
```
    Parent ID      : 563095369037b89a
    ID             : a32a194cc8c31afa
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 12:43:43.026681218 +0000 UTC
    End time       : 2026-07-14 12:43:43.026717759 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.start)
     -> http.status_code: Int(200)
Span #5
    Trace ID       : a8bf16a28da50792b6cead9a247651a6
    Parent ID      : 563095369037b89a
    ID             : 56b5b8a697d2b168
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 12:43:43.026922426 +0000 UTC
    End time       : 2026-07-14 12:43:43.026931926 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #6
    Trace ID       : a8bf16a28da50792b6cead9a247651a6
    Parent ID      : 563095369037b89a
    ID             : 11b0b23d94c28aff
    Name           : GET /api/v1/readyz http send
    Kind           : Internal
    Start time     : 2026-07-14 12:43:43.026981759 +0000 UTC
    End time       : 2026-07-14 12:43:43.026988968 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> asgi.event.type: Str(http.response.body)
Span #7
    Trace ID       : a8bf16a28da50792b6cead9a247651a6
    Parent ID      :
    ID             : 563095369037b89a
    Name           : GET /api/v1/readyz
    Kind           : Server
    Start time     : 2026-07-14 12:43:43.001202884 +0000 UTC
    End time       : 2026-07-14 12:43:43.027072009 +0000 UTC
    Status code    : Unset
    Status message :
Attributes:
     -> http.scheme: Str(https)
     -> http.host: Str(10.244.0.29:8443)
     -> net.host.port: Int(8443)
     -> http.flavor: Str(1.1)
     -> http.target: Str(/api/v1/readyz)
     -> http.url: Str(https://10.244.0.29:8443/api/v1/readyz)
     -> http.method: Str(GET)
     -> http.server_name: Str(10.244.0.29:8443)
     -> http.user_agent: Str(kube-probe/1.36)
     -> net.peer.ip: Str(10.244.0.1)
     -> net.peer.port: Int(60738)
     -> http.route: Str(/api/v1/readyz)
     -> http.status_code: Int(200)
	{"kind": "exporter", "data_type": "traces", "name": "debug"}
```
- AgentOS pod logs (tail 180):
```
{"ts": "2026-07-14 12:39:20,937", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-48da1af4bd2448d0a45fad7ffda8ed97", "trace_id": "ff1fabd86a87bf87892cf84f1c96dea1", "span_id": "bf2048858d373815", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:20,937", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-48da1af4bd2448d0a45fad7ffda8ed97", "trace_id": "ff1fabd86a87bf87892cf84f1c96dea1", "span_id": "bf2048858d373815", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 11.697, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 12:39:20,940", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-1931c56011a44b49a290a36db74d37f0", "trace_id": "0daabcdcb88b97024e3f882605b7881b", "span_id": "3cb780c2810773d3", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:20,940", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1931c56011a44b49a290a36db74d37f0", "trace_id": "0daabcdcb88b97024e3f882605b7881b", "span_id": "3cb780c2810773d3", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 8.104, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-f7345d2657d74ee8aff2485f74f77b79", "trace_id": "4bf76364886ba08dc0ed263ccc0d45b9", "span_id": "62e8e92c273c8d7d", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f7345d2657d74ee8aff2485f74f77b79", "trace_id": "4bf76364886ba08dc0ed263ccc0d45b9", "span_id": "62e8e92c273c8d7d", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 79.939, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-906d889333694c1899dd48fda324589d", "trace_id": "007fa4d57bcc54192da886b812829578", "span_id": "ce96dfdaec3c02d2", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-906d889333694c1899dd48fda324589d", "trace_id": "007fa4d57bcc54192da886b812829578", "span_id": "ce96dfdaec3c02d2", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 79.712, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-318f5ed63c5349279d916f9807e136ea", "trace_id": "49ac59709f18c2479246d0b128925f52", "span_id": "bb10abec6a267649", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-318f5ed63c5349279d916f9807e136ea", "trace_id": "49ac59709f18c2479246d0b128925f52", "span_id": "bb10abec6a267649", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 79.224, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c0b9e96ee8d24c6abaff9285ff9b8ce0", "trace_id": "c5f1c148e8fb6b7ba2e8b9891415e50d", "span_id": "f8eaba968389e128", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:21,014", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c0b9e96ee8d24c6abaff9285ff9b8ce0", "trace_id": "c5f1c148e8fb6b7ba2e8b9891415e50d", "span_id": "f8eaba968389e128", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 82.032, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 12:39:21,015", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-52c91baca43f4ccf9fb2bca3199421bb", "trace_id": "3f305b62112b38efefcf7cf567cf437d", "span_id": "bf2bf605ed753ccc", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:21,016", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-52c91baca43f4ccf9fb2bca3199421bb", "trace_id": "3f305b62112b38efefcf7cf567cf437d", "span_id": "bf2bf605ed753ccc", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 82.527, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 12:39:23,003", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-dfde06cec3fe4e5189ecaedcec511c02", "trace_id": "c63a32d5a9729a3b2d8f45f061f9f725", "span_id": "f45870e1cf455a6c"}
{"ts": "2026-07-14 12:39:23,012", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-dfde06cec3fe4e5189ecaedcec511c02", "trace_id": "c63a32d5a9729a3b2d8f45f061f9f725", "span_id": "f45870e1cf455a6c"}
{"ts": "2026-07-14 12:39:23,020", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-dfde06cec3fe4e5189ecaedcec511c02", "trace_id": "c63a32d5a9729a3b2d8f45f061f9f725", "span_id": "f45870e1cf455a6c"}
{"ts": "2026-07-14 12:39:23,020", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-dfde06cec3fe4e5189ecaedcec511c02", "trace_id": "c63a32d5a9729a3b2d8f45f061f9f725", "span_id": "f45870e1cf455a6c", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.707, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:39:24,580", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d48a10a5815c4b14878f0688b9ce9f50", "trace_id": "e4091492132a55bba7301a5803c3b2c6", "span_id": "049b1221c4c5f77c", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:24,581", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d48a10a5815c4b14878f0688b9ce9f50", "trace_id": "e4091492132a55bba7301a5803c3b2c6", "span_id": "049b1221c4c5f77c", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.777, "client_addr": "10.244.0.30"}
{"ts": "2026-07-14 12:39:26,685", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d231d3c1d4d14b72acdaa0e88601f3ae", "trace_id": "b2c0e04dcb7c463ee3e6fc8210726f39", "span_id": "0053ebe7b22f3b13", "tenant_id": "proof-foreign", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#31316dc7-5ad0-515e-a333-7ec9301118c7", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:26,685", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d231d3c1d4d14b72acdaa0e88601f3ae", "trace_id": "b2c0e04dcb7c463ee3e6fc8210726f39", "span_id": "0053ebe7b22f3b13", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.134, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 12:39:27,318", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-aaaf63f7ced54339bdc41d464bb8dd79", "trace_id": "87c69d2c23148bebd742e2ea7adced0a", "span_id": "fa990cf220507e20", "tenant_id": "proof-foreign", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#31316dc7-5ad0-515e-a333-7ec9301118c7", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:27,318", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-aaaf63f7ced54339bdc41d464bb8dd79", "trace_id": "87c69d2c23148bebd742e2ea7adced0a", "span_id": "fa990cf220507e20", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.706, "client_addr": "10.244.0.26"}
{"ts": "2026-07-14 12:39:27,584", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ce6f14b8ee344182b81a1458398446d9", "trace_id": "ce9b4ce39e90be8bb8c71d9bfac7fb04", "span_id": "c006488317aa0f12", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.096, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:39:33,000", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ac17ae7155524eda8d5279f916e5193e", "trace_id": "e5e1a34f3f2c0b46c84a8b19d74d8e78", "span_id": "c2a8b030ef089f44"}
{"ts": "2026-07-14 12:39:33,010", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ac17ae7155524eda8d5279f916e5193e", "trace_id": "e5e1a34f3f2c0b46c84a8b19d74d8e78", "span_id": "c2a8b030ef089f44"}
{"ts": "2026-07-14 12:39:33,018", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ac17ae7155524eda8d5279f916e5193e", "trace_id": "e5e1a34f3f2c0b46c84a8b19d74d8e78", "span_id": "c2a8b030ef089f44"}
{"ts": "2026-07-14 12:39:33,019", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ac17ae7155524eda8d5279f916e5193e", "trace_id": "e5e1a34f3f2c0b46c84a8b19d74d8e78", "span_id": "c2a8b030ef089f44", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.195, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:39:42,130", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-e3d613d22bb2446893ac5327e1272b72", "trace_id": "b907abebe923c31efe285f1e8c3080df", "span_id": "b9c1707b430440fe", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:42,130", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e3d613d22bb2446893ac5327e1272b72", "trace_id": "b907abebe923c31efe285f1e8c3080df", "span_id": "b9c1707b430440fe", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.05, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:39:42,588", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-88cf88efeff04cdc9bcbd2bf36155ac0", "trace_id": "0c7a7c34374358b60881a3f840084298", "span_id": "1d92e42b93de7248", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.276, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:39:42,750", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ef548dece0f149e4bbbf6dc384a895ad", "trace_id": "0c6925895903e7f9278ecc859466c5a0", "span_id": "683c87b58315382f", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:39:42,750", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ef548dece0f149e4bbbf6dc384a895ad", "trace_id": "0c6925895903e7f9278ecc859466c5a0", "span_id": "683c87b58315382f", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.363, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:39:43,003", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e7712b377bed48e5a6d62bed07a09e69", "trace_id": "f5d18fe3ef791cad45c4e4896dd244bf", "span_id": "5d064766b2f2c599"}
{"ts": "2026-07-14 12:39:43,012", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e7712b377bed48e5a6d62bed07a09e69", "trace_id": "f5d18fe3ef791cad45c4e4896dd244bf", "span_id": "5d064766b2f2c599"}
{"ts": "2026-07-14 12:39:43,022", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-e7712b377bed48e5a6d62bed07a09e69", "trace_id": "f5d18fe3ef791cad45c4e4896dd244bf", "span_id": "5d064766b2f2c599"}
{"ts": "2026-07-14 12:39:43,022", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e7712b377bed48e5a6d62bed07a09e69", "trace_id": "f5d18fe3ef791cad45c4e4896dd244bf", "span_id": "5d064766b2f2c599", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.236, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:39:53,003", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d1b45f1513d346c98947a65ae7c1549d", "trace_id": "8247043793090502b8f4f617afb1aca0", "span_id": "add2e84616b819a9"}
{"ts": "2026-07-14 12:39:53,013", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d1b45f1513d346c98947a65ae7c1549d", "trace_id": "8247043793090502b8f4f617afb1aca0", "span_id": "add2e84616b819a9"}
{"ts": "2026-07-14 12:39:53,021", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d1b45f1513d346c98947a65ae7c1549d", "trace_id": "8247043793090502b8f4f617afb1aca0", "span_id": "add2e84616b819a9"}
{"ts": "2026-07-14 12:39:53,022", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d1b45f1513d346c98947a65ae7c1549d", "trace_id": "8247043793090502b8f4f617afb1aca0", "span_id": "add2e84616b819a9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.993, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:39:57,589", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d06e96285f424931af0f46f88e7024f7", "trace_id": "edef3b0a67424c4e72c36119052bc45e", "span_id": "9b9f5ae629134281", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.245, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:03,005", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1c3d44e2be5445c497d94731f7e3d7be", "trace_id": "627d4f18222769f505fa349b00b31aa3", "span_id": "72e323a308b7ec4f"}
{"ts": "2026-07-14 12:40:03,014", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1c3d44e2be5445c497d94731f7e3d7be", "trace_id": "627d4f18222769f505fa349b00b31aa3", "span_id": "72e323a308b7ec4f"}
{"ts": "2026-07-14 12:40:03,022", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1c3d44e2be5445c497d94731f7e3d7be", "trace_id": "627d4f18222769f505fa349b00b31aa3", "span_id": "72e323a308b7ec4f"}
{"ts": "2026-07-14 12:40:03,023", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1c3d44e2be5445c497d94731f7e3d7be", "trace_id": "627d4f18222769f505fa349b00b31aa3", "span_id": "72e323a308b7ec4f", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.727, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:12,588", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d781e51177b741668c45d7d96a6a3ab4", "trace_id": "4bf628819966e1251ec8d471b4e2d11b", "span_id": "070e035759a6a635", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.219, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:13,002", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5d98a0ab1af743708be5f7f8fbab4d92", "trace_id": "4cc38fe61781404b35ae6982db23a762", "span_id": "ea3cc0eca533c4e1"}
{"ts": "2026-07-14 12:40:13,012", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5d98a0ab1af743708be5f7f8fbab4d92", "trace_id": "4cc38fe61781404b35ae6982db23a762", "span_id": "ea3cc0eca533c4e1"}
{"ts": "2026-07-14 12:40:13,020", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5d98a0ab1af743708be5f7f8fbab4d92", "trace_id": "4cc38fe61781404b35ae6982db23a762", "span_id": "ea3cc0eca533c4e1"}
{"ts": "2026-07-14 12:40:13,020", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5d98a0ab1af743708be5f7f8fbab4d92", "trace_id": "4cc38fe61781404b35ae6982db23a762", "span_id": "ea3cc0eca533c4e1", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.687, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:23,007", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3298dd6db697428f841dda668389cf0d", "trace_id": "1fb2576b5eebbe167138ab997336810d", "span_id": "378954d24531d406"}
{"ts": "2026-07-14 12:40:23,016", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3298dd6db697428f841dda668389cf0d", "trace_id": "1fb2576b5eebbe167138ab997336810d", "span_id": "378954d24531d406"}
{"ts": "2026-07-14 12:40:23,024", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3298dd6db697428f841dda668389cf0d", "trace_id": "1fb2576b5eebbe167138ab997336810d", "span_id": "378954d24531d406"}
{"ts": "2026-07-14 12:40:23,025", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3298dd6db697428f841dda668389cf0d", "trace_id": "1fb2576b5eebbe167138ab997336810d", "span_id": "378954d24531d406", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.142, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:27,588", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-af5507a6434d4be99e532a219f92f6fe", "trace_id": "21fce484a2bcc1ede82377a074443b57", "span_id": "859ff166fdf9fbdb", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.236, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:33,002", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-74b3adab20494f50b7a73f49ab86e39f", "trace_id": "40be5a58bc5c9e8be857a3f27ca2efd1", "span_id": "98df55b53d4aa05d"}
{"ts": "2026-07-14 12:40:33,012", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-74b3adab20494f50b7a73f49ab86e39f", "trace_id": "40be5a58bc5c9e8be857a3f27ca2efd1", "span_id": "98df55b53d4aa05d"}
{"ts": "2026-07-14 12:40:33,020", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-74b3adab20494f50b7a73f49ab86e39f", "trace_id": "40be5a58bc5c9e8be857a3f27ca2efd1", "span_id": "98df55b53d4aa05d"}
{"ts": "2026-07-14 12:40:33,020", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-74b3adab20494f50b7a73f49ab86e39f", "trace_id": "40be5a58bc5c9e8be857a3f27ca2efd1", "span_id": "98df55b53d4aa05d", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.812, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:42,586", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-66a33e3996e24e2d895ab9dde2230931", "trace_id": "57f66dff82d9f1bddd1bf26df56efeb8", "span_id": "fa6b62f4899e95bd", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.239, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:43,004", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-11a3a1c499e543bdb00e1646a34e5658", "trace_id": "8b45eb3ce1ee867261cd2eee0c0d5e1d", "span_id": "db403dc551703f50"}
{"ts": "2026-07-14 12:40:43,012", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-11a3a1c499e543bdb00e1646a34e5658", "trace_id": "8b45eb3ce1ee867261cd2eee0c0d5e1d", "span_id": "db403dc551703f50"}
{"ts": "2026-07-14 12:40:43,021", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-11a3a1c499e543bdb00e1646a34e5658", "trace_id": "8b45eb3ce1ee867261cd2eee0c0d5e1d", "span_id": "db403dc551703f50"}
{"ts": "2026-07-14 12:40:43,021", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-11a3a1c499e543bdb00e1646a34e5658", "trace_id": "8b45eb3ce1ee867261cd2eee0c0d5e1d", "span_id": "db403dc551703f50", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.281, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:53,002", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-658007a108d04028b22c93833db48a3b", "trace_id": "149e729054548a4cf7674007825b4e0d", "span_id": "769220fe9b9b05e9"}
{"ts": "2026-07-14 12:40:53,011", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-658007a108d04028b22c93833db48a3b", "trace_id": "149e729054548a4cf7674007825b4e0d", "span_id": "769220fe9b9b05e9"}
{"ts": "2026-07-14 12:40:53,020", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-658007a108d04028b22c93833db48a3b", "trace_id": "149e729054548a4cf7674007825b4e0d", "span_id": "769220fe9b9b05e9"}
{"ts": "2026-07-14 12:40:53,020", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-658007a108d04028b22c93833db48a3b", "trace_id": "149e729054548a4cf7674007825b4e0d", "span_id": "769220fe9b9b05e9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.492, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:57,582", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1ac9f6e25f0e4ed2b990e896c6c5cb05", "trace_id": "41bd7a7ae8377f1d342cb25e048230b2", "span_id": "c720b2d0febd2e37", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.118, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:40:59,157", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-d638dcece8c74cb49a0750f0fdba3f5d", "trace_id": "aa5c296e67e3637eaf92961fc97e5b94", "span_id": "4ef79a5887de7725", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:40:59,157", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d638dcece8c74cb49a0750f0fdba3f5d", "trace_id": "aa5c296e67e3637eaf92961fc97e5b94", "span_id": "4ef79a5887de7725", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.041, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:41:02,997", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cf466d6a3ad94180891927edf7dbe2bb", "trace_id": "a0cafc962c98290339fc7bd7a770dd21", "span_id": "4ae7f02d3620235e"}
{"ts": "2026-07-14 12:41:03,005", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cf466d6a3ad94180891927edf7dbe2bb", "trace_id": "a0cafc962c98290339fc7bd7a770dd21", "span_id": "4ae7f02d3620235e"}
{"ts": "2026-07-14 12:41:03,013", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-cf466d6a3ad94180891927edf7dbe2bb", "trace_id": "a0cafc962c98290339fc7bd7a770dd21", "span_id": "4ae7f02d3620235e"}
{"ts": "2026-07-14 12:41:03,014", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-cf466d6a3ad94180891927edf7dbe2bb", "trace_id": "a0cafc962c98290339fc7bd7a770dd21", "span_id": "4ae7f02d3620235e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 19.648, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:12,586", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-8d2eed1fc1854e538b96b8805feeb1cc", "trace_id": "ef36f3ad11e1f0467e6f307432c0736d", "span_id": "4caa332214508668", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.21, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:13,005", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f17947ec18f64a80a8e021e7656bcaf1", "trace_id": "a02d885b919ab220aeb4185cbbafa488", "span_id": "4f74a119598469ab"}
{"ts": "2026-07-14 12:41:13,015", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f17947ec18f64a80a8e021e7656bcaf1", "trace_id": "a02d885b919ab220aeb4185cbbafa488", "span_id": "4f74a119598469ab"}
{"ts": "2026-07-14 12:41:13,026", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-f17947ec18f64a80a8e021e7656bcaf1", "trace_id": "a02d885b919ab220aeb4185cbbafa488", "span_id": "4f74a119598469ab"}
{"ts": "2026-07-14 12:41:13,027", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-f17947ec18f64a80a8e021e7656bcaf1", "trace_id": "a02d885b919ab220aeb4185cbbafa488", "span_id": "4f74a119598469ab", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 27.2, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:14,377", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-a0c7311a4fe246a3996d485f8db45ca8", "trace_id": "7d0fa2f498268cade0799f0a1ea5880f", "span_id": "c969d1391b5b6bfc", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:41:14,377", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a0c7311a4fe246a3996d485f8db45ca8", "trace_id": "7d0fa2f498268cade0799f0a1ea5880f", "span_id": "c969d1391b5b6bfc", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.093, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:41:23,005", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-48d43a12e7af4939b4c27ca9c470f5e5", "trace_id": "b8bcc31ac64960fb30838982058d6490", "span_id": "50a579d57c78c3c7"}
{"ts": "2026-07-14 12:41:23,014", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-48d43a12e7af4939b4c27ca9c470f5e5", "trace_id": "b8bcc31ac64960fb30838982058d6490", "span_id": "50a579d57c78c3c7"}
{"ts": "2026-07-14 12:41:23,024", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-48d43a12e7af4939b4c27ca9c470f5e5", "trace_id": "b8bcc31ac64960fb30838982058d6490", "span_id": "50a579d57c78c3c7"}
{"ts": "2026-07-14 12:41:23,025", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-48d43a12e7af4939b4c27ca9c470f5e5", "trace_id": "b8bcc31ac64960fb30838982058d6490", "span_id": "50a579d57c78c3c7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.648, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:27,587", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e0b0ddd62b754259aea7138b70eff003", "trace_id": "b94e22863bc56221b3cf89d309fe78e1", "span_id": "9aa200c01da0a365", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.217, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:29,426", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-4bbbe1a8829e47ac8f0f028920740cb1", "trace_id": "000074953f8e0518e6618ac38744b273", "span_id": "eccd12953b4b6c2c", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:41:29,427", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-4bbbe1a8829e47ac8f0f028920740cb1", "trace_id": "000074953f8e0518e6618ac38744b273", "span_id": "eccd12953b4b6c2c", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.159, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:41:33,003", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3dddef9f942144e79ae150233329b7a3", "trace_id": "2bd971cec88f15371ae2d7356e7231cf", "span_id": "c0d6b684191fb2fb"}
{"ts": "2026-07-14 12:41:33,013", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3dddef9f942144e79ae150233329b7a3", "trace_id": "2bd971cec88f15371ae2d7356e7231cf", "span_id": "c0d6b684191fb2fb"}
{"ts": "2026-07-14 12:41:33,021", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-3dddef9f942144e79ae150233329b7a3", "trace_id": "2bd971cec88f15371ae2d7356e7231cf", "span_id": "c0d6b684191fb2fb"}
{"ts": "2026-07-14 12:41:33,022", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-3dddef9f942144e79ae150233329b7a3", "trace_id": "2bd971cec88f15371ae2d7356e7231cf", "span_id": "c0d6b684191fb2fb", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.431, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:42,587", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-00a9a6e1ad9e4079b80ee0fcae951ba6", "trace_id": "efcf0f403cff4f25c5bbf5c8c764d801", "span_id": "64722f818614ed54", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.185, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:43,003", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ee5083de09a0474bbb3c5217d9696678", "trace_id": "77a06abe6e580017259aba28e4a6c443", "span_id": "6eedcb8c50ecfba2"}
{"ts": "2026-07-14 12:41:43,011", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ee5083de09a0474bbb3c5217d9696678", "trace_id": "77a06abe6e580017259aba28e4a6c443", "span_id": "6eedcb8c50ecfba2"}
{"ts": "2026-07-14 12:41:43,020", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ee5083de09a0474bbb3c5217d9696678", "trace_id": "77a06abe6e580017259aba28e4a6c443", "span_id": "6eedcb8c50ecfba2"}
{"ts": "2026-07-14 12:41:43,020", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ee5083de09a0474bbb3c5217d9696678", "trace_id": "77a06abe6e580017259aba28e4a6c443", "span_id": "6eedcb8c50ecfba2", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 23.25, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:44,473", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-c5ad149d28ad493aa02ea06d26304497", "trace_id": "b5f415a0cfa1aaadcc041461445c8056", "span_id": "aeca2fb4297b0da9", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:41:44,473", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c5ad149d28ad493aa02ea06d26304497", "trace_id": "b5f415a0cfa1aaadcc041461445c8056", "span_id": "aeca2fb4297b0da9", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.772, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:41:53,003", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5cbf86614ac5427da3494326fcc91c5f", "trace_id": "dac1e61f19773e4e71f9c95a6abef325", "span_id": "17303d7b6e6a1ee7"}
{"ts": "2026-07-14 12:41:53,011", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5cbf86614ac5427da3494326fcc91c5f", "trace_id": "dac1e61f19773e4e71f9c95a6abef325", "span_id": "17303d7b6e6a1ee7"}
{"ts": "2026-07-14 12:41:53,020", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-5cbf86614ac5427da3494326fcc91c5f", "trace_id": "dac1e61f19773e4e71f9c95a6abef325", "span_id": "17303d7b6e6a1ee7"}
{"ts": "2026-07-14 12:41:53,020", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5cbf86614ac5427da3494326fcc91c5f", "trace_id": "dac1e61f19773e4e71f9c95a6abef325", "span_id": "17303d7b6e6a1ee7", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 20.525, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:57,588", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-49df074cd31d4a3388c8ee060cd77878", "trace_id": "0b8e99bec3f6edbcda2249993f231881", "span_id": "6843a6f07738f70b", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.2, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:41:59,524", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-a77d71192b3c42ee85a5a9f8580e3a3d", "trace_id": "6456560d293639c40933f7b1fc8a5673", "span_id": "e61f9a36af442196", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:41:59,524", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-a77d71192b3c42ee85a5a9f8580e3a3d", "trace_id": "6456560d293639c40933f7b1fc8a5673", "span_id": "e61f9a36af442196", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.95, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:42:03,004", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bed09358e8f443aaaa4b4c155911def9", "trace_id": "76f09f26072a9a07ac914a7a1ff9957b", "span_id": "0d696429734d835e"}
{"ts": "2026-07-14 12:42:03,012", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bed09358e8f443aaaa4b4c155911def9", "trace_id": "76f09f26072a9a07ac914a7a1ff9957b", "span_id": "0d696429734d835e"}
{"ts": "2026-07-14 12:42:03,021", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-bed09358e8f443aaaa4b4c155911def9", "trace_id": "76f09f26072a9a07ac914a7a1ff9957b", "span_id": "0d696429734d835e"}
{"ts": "2026-07-14 12:42:03,022", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bed09358e8f443aaaa4b4c155911def9", "trace_id": "76f09f26072a9a07ac914a7a1ff9957b", "span_id": "0d696429734d835e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.518, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:12,591", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-41a1c6182b0d46e0986de30ac34960b3", "trace_id": "d36929fcdd63579812d41d1ac1417d17", "span_id": "3a29cc38df70726f", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.251, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:13,008", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-83a53834e08b4e64bb85f90fcc93dbe6", "trace_id": "bb5ef19dcc367e9c7a53eaee13a25432", "span_id": "26b8681bc726d20a"}
{"ts": "2026-07-14 12:42:13,017", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-83a53834e08b4e64bb85f90fcc93dbe6", "trace_id": "bb5ef19dcc367e9c7a53eaee13a25432", "span_id": "26b8681bc726d20a"}
{"ts": "2026-07-14 12:42:13,025", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-83a53834e08b4e64bb85f90fcc93dbe6", "trace_id": "bb5ef19dcc367e9c7a53eaee13a25432", "span_id": "26b8681bc726d20a"}
{"ts": "2026-07-14 12:42:13,025", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-83a53834e08b4e64bb85f90fcc93dbe6", "trace_id": "bb5ef19dcc367e9c7a53eaee13a25432", "span_id": "26b8681bc726d20a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.567, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:14,582", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-bc0463b4c355461194afcf712d82dc27", "trace_id": "d7c9a02dd5757d3d4cda4ff06c046b04", "span_id": "de798fe66761787a", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:42:14,582", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bc0463b4c355461194afcf712d82dc27", "trace_id": "d7c9a02dd5757d3d4cda4ff06c046b04", "span_id": "de798fe66761787a", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.165, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:42:23,006", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ec64f48025e542c9bf2671b8745583e6", "trace_id": "f962586335d339c10e48601a8db7d48d", "span_id": "5577ab97704f946b"}
{"ts": "2026-07-14 12:42:23,015", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ec64f48025e542c9bf2671b8745583e6", "trace_id": "f962586335d339c10e48601a8db7d48d", "span_id": "5577ab97704f946b"}
{"ts": "2026-07-14 12:42:23,024", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ec64f48025e542c9bf2671b8745583e6", "trace_id": "f962586335d339c10e48601a8db7d48d", "span_id": "5577ab97704f946b"}
{"ts": "2026-07-14 12:42:23,024", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ec64f48025e542c9bf2671b8745583e6", "trace_id": "f962586335d339c10e48601a8db7d48d", "span_id": "5577ab97704f946b", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.874, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:27,592", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-152ec7eecacc4abe8c80ba1a9d82575c", "trace_id": "60b82374c7b0820383a229c119a3cf1c", "span_id": "7df6ba81ce959920", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.233, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:29,637", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-5a87eb1a3e384b41ad90c81b5c8f6d87", "trace_id": "256c365fa984319e73ca7ad2234c84cc", "span_id": "2373c18025ae80b5", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:42:29,637", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-5a87eb1a3e384b41ad90c81b5c8f6d87", "trace_id": "256c365fa984319e73ca7ad2234c84cc", "span_id": "2373c18025ae80b5", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.627, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:42:33,008", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-400584aa9a704c118ec73f61c9c26485", "trace_id": "29b3f0a8a2ca847ffb863d659cb263e8", "span_id": "d5c1798216065f56"}
{"ts": "2026-07-14 12:42:33,016", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-400584aa9a704c118ec73f61c9c26485", "trace_id": "29b3f0a8a2ca847ffb863d659cb263e8", "span_id": "d5c1798216065f56"}
{"ts": "2026-07-14 12:42:33,024", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-400584aa9a704c118ec73f61c9c26485", "trace_id": "29b3f0a8a2ca847ffb863d659cb263e8", "span_id": "d5c1798216065f56"}
{"ts": "2026-07-14 12:42:33,024", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-400584aa9a704c118ec73f61c9c26485", "trace_id": "29b3f0a8a2ca847ffb863d659cb263e8", "span_id": "d5c1798216065f56", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.682, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:42,590", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-bc7c2ca3960646c795dea3dc36a25093", "trace_id": "4ad1737bbee2a889c68400168a4b3ccd", "span_id": "2c00b239dd6f4397", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.236, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:43,006", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c8e0565c61884f2cba734efbb193a437", "trace_id": "6c6382edaaeee7dddebdbf24d583949b", "span_id": "3ca4bd72a9412cfa"}
{"ts": "2026-07-14 12:42:43,014", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c8e0565c61884f2cba734efbb193a437", "trace_id": "6c6382edaaeee7dddebdbf24d583949b", "span_id": "3ca4bd72a9412cfa"}
{"ts": "2026-07-14 12:42:43,024", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-c8e0565c61884f2cba734efbb193a437", "trace_id": "6c6382edaaeee7dddebdbf24d583949b", "span_id": "3ca4bd72a9412cfa"}
{"ts": "2026-07-14 12:42:43,024", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-c8e0565c61884f2cba734efbb193a437", "trace_id": "6c6382edaaeee7dddebdbf24d583949b", "span_id": "3ca4bd72a9412cfa", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.713, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:44,686", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-ab0b1d0ae11e41fba63251b070f48594", "trace_id": "a7fd36625a9e33b785aa5c7886e02e5b", "span_id": "e039b2b0d19b0f45", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:42:44,687", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ab0b1d0ae11e41fba63251b070f48594", "trace_id": "a7fd36625a9e33b785aa5c7886e02e5b", "span_id": "e039b2b0d19b0f45", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.074, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:42:53,006", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0bff40a2cace471f82bd7263972854f3", "trace_id": "8afa4620159030bc1a1a3efd9c6d3319", "span_id": "ed97bf8b926d07a9"}
{"ts": "2026-07-14 12:42:53,015", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0bff40a2cace471f82bd7263972854f3", "trace_id": "8afa4620159030bc1a1a3efd9c6d3319", "span_id": "ed97bf8b926d07a9"}
{"ts": "2026-07-14 12:42:53,023", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-0bff40a2cace471f82bd7263972854f3", "trace_id": "8afa4620159030bc1a1a3efd9c6d3319", "span_id": "ed97bf8b926d07a9"}
{"ts": "2026-07-14 12:42:53,024", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-0bff40a2cace471f82bd7263972854f3", "trace_id": "8afa4620159030bc1a1a3efd9c6d3319", "span_id": "ed97bf8b926d07a9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.424, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:57,590", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-992d7f9011e5431b9ee46e3e9ba20b87", "trace_id": "8a237729e20380ea59bfedd2a37a84f7", "span_id": "9cf5f6dc4e5c780a", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.202, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:42:59,743", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-73ce28c700254124ae1d0fdec8c3c3b1", "trace_id": "e50dff4aef122d6b1cd0827592cb8d7a", "span_id": "29444886df9a3d82", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:42:59,743", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-73ce28c700254124ae1d0fdec8c3c3b1", "trace_id": "e50dff4aef122d6b1cd0827592cb8d7a", "span_id": "29444886df9a3d82", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.734, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:43:00,181", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-7bb842128e57470abc2c3694d253455c", "trace_id": "d4bade5e5c75d86484b79086741b8b6a", "span_id": "6d62f6d02f64e990", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:43:00,181", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-7bb842128e57470abc2c3694d253455c", "trace_id": "d4bade5e5c75d86484b79086741b8b6a", "span_id": "6d62f6d02f64e990", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 1.928, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:43:03,006", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-67c8fac7f4004678b0a9a9713ab23fb8", "trace_id": "37eef39245a28991cfe1cb4e20aa598a", "span_id": "8b33e56bab9155d9"}
{"ts": "2026-07-14 12:43:03,015", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-67c8fac7f4004678b0a9a9713ab23fb8", "trace_id": "37eef39245a28991cfe1cb4e20aa598a", "span_id": "8b33e56bab9155d9"}
{"ts": "2026-07-14 12:43:03,023", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-67c8fac7f4004678b0a9a9713ab23fb8", "trace_id": "37eef39245a28991cfe1cb4e20aa598a", "span_id": "8b33e56bab9155d9"}
{"ts": "2026-07-14 12:43:03,024", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-67c8fac7f4004678b0a9a9713ab23fb8", "trace_id": "37eef39245a28991cfe1cb4e20aa598a", "span_id": "8b33e56bab9155d9", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 22.686, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:12,594", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-229d9debf90b42eaadc1d05c640b1215", "trace_id": "0429d61111fb2619d2f18d1ee0c34497", "span_id": "97a941758b3b2773", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.213, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:13,006", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d3dc25f4eaf945c4a6fc7d952d13480a", "trace_id": "620cc8c38ef9c3dd4bef38c327352821", "span_id": "ed4559a099bc33b6"}
{"ts": "2026-07-14 12:43:13,015", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d3dc25f4eaf945c4a6fc7d952d13480a", "trace_id": "620cc8c38ef9c3dd4bef38c327352821", "span_id": "ed4559a099bc33b6"}
{"ts": "2026-07-14 12:43:13,023", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-d3dc25f4eaf945c4a6fc7d952d13480a", "trace_id": "620cc8c38ef9c3dd4bef38c327352821", "span_id": "ed4559a099bc33b6"}
{"ts": "2026-07-14 12:43:13,023", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-d3dc25f4eaf945c4a6fc7d952d13480a", "trace_id": "620cc8c38ef9c3dd4bef38c327352821", "span_id": "ed4559a099bc33b6", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.365, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:14,396", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-1112d3d2b4c0443d88f8175dc07c5a09", "trace_id": "4fe6faed22320cba1ad53d2b7bf11955", "span_id": "2db7045d995e09cc", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#9303042b-42e8-50a5-bf2d-dd88346916bc", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:43:14,396", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1112d3d2b4c0443d88f8175dc07c5a09", "trace_id": "4fe6faed22320cba1ad53d2b7bf11955", "span_id": "2db7045d995e09cc", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.422, "client_addr": "10.244.0.32"}
{"ts": "2026-07-14 12:43:23,005", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-173200fae5a844fbad9b3ce7a6cc6f94", "trace_id": "262eaf7a243e45772c11b59e5c0a8709", "span_id": "f37f36ece3884350"}
{"ts": "2026-07-14 12:43:23,013", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-173200fae5a844fbad9b3ce7a6cc6f94", "trace_id": "262eaf7a243e45772c11b59e5c0a8709", "span_id": "f37f36ece3884350"}
{"ts": "2026-07-14 12:43:23,022", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-173200fae5a844fbad9b3ce7a6cc6f94", "trace_id": "262eaf7a243e45772c11b59e5c0a8709", "span_id": "f37f36ece3884350"}
{"ts": "2026-07-14 12:43:23,022", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-173200fae5a844fbad9b3ce7a6cc6f94", "trace_id": "262eaf7a243e45772c11b59e5c0a8709", "span_id": "f37f36ece3884350", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 21.479, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:27,589", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1a916c1dd4844b5fbca53d6f57bf852d", "trace_id": "cc3ad037cc711ba850d477f3709cec84", "span_id": "35848a6734be7e19", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.198, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:33,024", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ef74086cf5f741b2af11fc333253e2d8", "trace_id": "0e7630c86b92bab273c72d02b3fd1886", "span_id": "fab44c98068d3a9a"}
{"ts": "2026-07-14 12:43:33,032", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ef74086cf5f741b2af11fc333253e2d8", "trace_id": "0e7630c86b92bab273c72d02b3fd1886", "span_id": "fab44c98068d3a9a"}
{"ts": "2026-07-14 12:43:33,039", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-ef74086cf5f741b2af11fc333253e2d8", "trace_id": "0e7630c86b92bab273c72d02b3fd1886", "span_id": "fab44c98068d3a9a"}
{"ts": "2026-07-14 12:43:33,040", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ef74086cf5f741b2af11fc333253e2d8", "trace_id": "0e7630c86b92bab273c72d02b3fd1886", "span_id": "fab44c98068d3a9a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 38.647, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:42,590", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-ce08bdf1c2fc4d0bb591b9986ca976bb", "trace_id": "80e4b24dff2edd01189a683c85110c27", "span_id": "56d1aa785bc67ba7", "http_method": "GET", "http_path": "/api/v1/healthz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 0.194, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:43,006", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-02a21d5b133a4a3eae24a96e65b832b4", "trace_id": "a8bf16a28da50792b6cead9a247651a6", "span_id": "563095369037b89a"}
{"ts": "2026-07-14 12:43:43,016", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-02a21d5b133a4a3eae24a96e65b832b4", "trace_id": "a8bf16a28da50792b6cead9a247651a6", "span_id": "563095369037b89a"}
{"ts": "2026-07-14 12:43:43,026", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-02a21d5b133a4a3eae24a96e65b832b4", "trace_id": "a8bf16a28da50792b6cead9a247651a6", "span_id": "563095369037b89a"}
{"ts": "2026-07-14 12:43:43,026", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-02a21d5b133a4a3eae24a96e65b832b4", "trace_id": "a8bf16a28da50792b6cead9a247651a6", "span_id": "563095369037b89a", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 24.881, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:53,013", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://qdrant:6333/collections \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1b4118358ea842d6835ab9fe41b4b587", "trace_id": "c6d053aa688228b8c2586c00574c1a06", "span_id": "b8e707bcf8234f6e"}
{"ts": "2026-07-14 12:43:53,021", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://ollama:11434/api/tags \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1b4118358ea842d6835ab9fe41b4b587", "trace_id": "c6d053aa688228b8c2586c00574c1a06", "span_id": "b8e707bcf8234f6e"}
{"ts": "2026-07-14 12:43:53,031", "level": "INFO", "logger": "httpx", "message": "HTTP Request: GET http://langfuse:3000/api/public/health \"HTTP/1.1 200 OK\"", "request_id": "portal-req-1b4118358ea842d6835ab9fe41b4b587", "trace_id": "c6d053aa688228b8c2586c00574c1a06", "span_id": "b8e707bcf8234f6e"}
{"ts": "2026-07-14 12:43:53,031", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-1b4118358ea842d6835ab9fe41b4b587", "trace_id": "c6d053aa688228b8c2586c00574c1a06", "span_id": "b8e707bcf8234f6e", "http_method": "GET", "http_path": "/api/v1/readyz", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 26.187, "client_addr": "10.244.0.1"}
{"ts": "2026-07-14 12:43:54,101", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fe45221bcb764c799d1f4a3cb32d14fd", "trace_id": "aba98cf72fbe8f38ecaf157d2ac20805", "span_id": "bf0913362bf13bf0", "http_method": "GET", "http_path": "/api/v1/approvals/", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 25.101, "client_addr": "10.244.0.34"}
{"ts": "2026-07-14 12:43:54,934", "level": "INFO", "logger": "cognic_agentos.portal.api.conversations.routes", "message": "portal.conversations.list", "request_id": "portal-req-e2c62e6ab8d0438fbe039a572b3bfd17", "trace_id": "b5ab17d684d8678aa486caa33e5dfa87", "span_id": "acef1f9b0084d293", "tenant_id": "proof-m85c", "actor_subject": "https://cognic-proof-keycloak:8443/realms/proof-m85c#a0a8afbd-da88-58b8-b8b9-0d1c21734660", "conversation_id": null, "seq": null, "outcome": "ok"}
{"ts": "2026-07-14 12:43:54,934", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-e2c62e6ab8d0438fbe039a572b3bfd17", "trace_id": "b5ab17d684d8678aa486caa33e5dfa87", "span_id": "acef1f9b0084d293", "http_method": "GET", "http_path": "/api/v1/conversations", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 200, "duration_ms": 2.203, "client_addr": "10.244.0.34"}
{"ts": "2026-07-14 12:43:55,329", "level": "INFO", "logger": "cognic_agentos.access", "message": "http_request", "request_id": "portal-req-fac6de92c52e4ff9b3e29f75c91ed283", "trace_id": "31594262340953871b6c6c54984f815f", "span_id": "18af77a2533883f3", "http_method": "POST", "http_path": "/api/v1/mcp/servers/cognic-tool-approval-probe/tools/call", "http_has_query": false, "http_query_param_count": 0, "http_status_code": 202, "duration_ms": 142.824, "client_addr": "127.0.0.1"}
```
