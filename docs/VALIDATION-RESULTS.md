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
