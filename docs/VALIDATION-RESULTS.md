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
