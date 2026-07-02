# Proof M5 — Real Hook Pack Proof (deployed DLP pre-invocation gate)

This proof stands up a `kind` cluster and proves the **ADR-017 DLP pre-invocation
gate** live against a deployed AgentOS kernel, using **two RELEASED, signed
packs** (released assets only — neither is built from source here):

* **`cognic-tool-oracle-schema@v0.2.0`** — the DLP-governed re-release of the
  M3/M4 tool. The delta is manifest-only: its `[data_governance]` block declares
  `dlp_pre_hooks = ["refuse_forbidden_schema_arg", "explode_schema_guard"]`. The
  tool server itself is unchanged; `v0.1.0` stays the M3/M4 evidence artifact.
* **`cognic-hook-schema-guard@v0.1.0`** — a new signed **hook pack** with two
  real, deterministic, no-LLM `dlp_pre` hooks registered under
  `[project.entry-points."cognic.hooks"]`. Both are **arg-gated** (each fires
  only on its own documented sentinel), so all three bars run against the single
  deployed `v0.2.0` tool with the **argument as the only variable**.

It **extends** the proven Proof M4 harness (multi-actor proof app + the governed
operator-install flow + in-cluster Oracle XE + RS256/JWKS AS + the single
effective MCP URL `10.96.0.51:8765/mcp`). The **delta is the DLP gate**: the M5
kernel branch wires `MCPHost.call_tool` to run the tool pack's declared
`dlp_pre_hooks` over the canonical call arguments **after** the static/approval
gates and **before** any token / session / transport work reaches the tool.

The kernel image is rebuilt **from this branch** (the runner overlays
`src/cognic_agentos` into the image) so the DLP wiring is baked in; every other
artefact here is proof-only.

## The trust-register vs operator-install split (spec §6, decision B)

The two packs deliberately take **different governance paths**:

* **The tool pack (`v0.2.0`) is operator-installed via the M4 flow.** The runner
  drives the real operator API — `submit → claim → approve → allow-list →
  configure → install` — and `install`'s materializer projects the derived MCP
  carve-out rows (server-url override + internal-host allow-list) from the
  configured runtime-config record, exactly as proven in M4. `seed-db.sh` stays
  a **no-op guard**.
* **The hook pack is trust-register + registry-admit ONLY.** Its wheel is baked
  into the **kernel image** (`Dockerfile.agentos-proof` pip-installs it into the
  kernel venv — it declares **zero runtime dependencies** by design) so boot
  trust-registration sees it via pack discovery and
  `PluginRegistry.iter_registered_pack_candidates()`; the hook-registry boot
  loader then admits its verified `[hooks]` declarations into the `HookRegistry`
  that backs the `DLPGuard` the MCP host consumes. It **never** enters the
  portal pack-lifecycle API — no lifecycle rows, no runtime-config record, no
  carve-out rows, nothing to materialize. Hooks are in-process kernel-loaded
  code, not an MCP service; their governance is the boot trust gate (cosign +
  per-tenant allow-list) plus verified-hook admission, and their operator
  lifecycle (enable/disable via an M4-style flow) is an explicit **follow-up**
  (spec §8), not an M5 requirement.

### Two-key trust staging (read before touching `stage-packs.sh`)

The two releases are signed with **different cosign keys**. The staging tree
therefore carries both, under the one `COGNIC_TRUST_ROOT_PREFIX`:

| Staged path | Key | Consumed by |
|---|---|---|
| `trust-roots/_default/cosign.pub` | oracle `v0.2.0` key | The kernel's **LOCKED** boot convention (`harness/registry_boot.py` verifies discovered packs against `<prefix>/_default/cosign.pub`) AND the approve 5-gate's signature root (`ProofStagedTrustRootResolver`). |
| `trust-roots/hook-packs/cognic-hook-schema-guard/cosign.pub` | hook pack key | The hook pack's trust registration. `hook-packs/` is **not** a tenant directory — it exists so the hook key canonicalises under the trust-root prefix (`trust_gate.py` path containment) for per-pack verification. |

The proof app + runner (Task 10/11) own the wiring that registers the hook pack
against its own key; the stock single-key boot loop would cosign-refuse it
against the `_default` (oracle) key and fail-soft skip it.

`stage-packs.sh` downloads both releases with `gh release download` and
**sha256-verifies every pinned asset digest fail-closed** (both wheels + both
`cosign.pub`s) before arranging the tree — a digest mismatch means the release
moved and the stage aborts; the pins are never silently re-pointed.

## How to run (operator-only, env-gated)

```bash
COGNIC_RUN_PROOF_M5=1 bash infra/proof-m5/run-proof-m5.sh
```

(`run-proof-m5.sh` is the Task-10 deliverable of the M5 plan; this scaffolding
commit ships everything the runner consumes — including `stage-packs.sh`, which
the runner calls at its stage step.) The runner is **env-gated**: with
`COGNIC_RUN_PROOF_M5` unset it prints a skip notice and exits `0` (inert in any
non-operator context, including CI). It needs `docker`, `kind`, `kubectl`,
`helm`, `uv`, `cosign`, `syft`, `grype`, `curl`, `python3`, and `gh` on `PATH`,
and deletes the `kind` cluster on exit.

## What it proves — the three DLP bars (spec §6)

All three bars call the same deployed `v0.2.0` tool through the governed MCP
route; the **hook decision is the only variable**:

* **BAR 1 — happy path (hook fires, allows — prints `PROOF M5 (BAR 1) PASS`).**
  `call_tool(describe_table, owner=COGNIC, table=EMPLOYEES)` with a **permitted**
  arg → the hook runs → allows → the tool executes → **200** with the seeded
  `EMPLOYEES` column `FULL_NAME`. Proves the hook fires *and* a clean call
  passes unchanged.
* **BAR 2 — load-bearing refusal (the closer — prints `PROOF M5 (BAR 2) PASS`).**
  `call_tool` with the **forbidden** arg (`table=__FORBIDDEN__`) →
  `refuse_forbidden_schema_arg` policy-refuses → **403 `dlp_pre_refused`** with
  `policy_reason=forbidden_schema_arg` — refused **before the tool runs** (no
  token / session / transport work reaches the AS or the tool server; no new
  tool audit row) and the audit evidence is **digest-only** (the forbidden
  literal never appears in the chain row). The per-argument binary — BAR 1
  permitted vs BAR 2 forbidden, same deployed pack — proves the control matters.
* **BAR 3 — fail-closed on hook failure (prints `PROOF M5 (BAR 3) PASS`).**
  `call_tool` with the **explode** arg (`table=__EXPLODE__`) → the first hook
  passes, `explode_schema_guard` raises → `dlp_dispatcher_failed` → **409
  `dlp_pre_failed`**. A broken hook is a refusal, never a silent bypass.

On any BAR failure the runner captures pod logs + status + the refusal reason to
`docs/VALIDATION-RESULTS.md` and exits non-zero — the proof is **never redefined
downward**.

## ⚠ Proof-only wiring — production needs a real overlay

The deployed image runs a **proof-only** `create_proof_app()` factory (vendored
as `proof_m5/` at image build; the M5 mirror of
`tests/integration/proof_m4/proof_app.py`). The M4 caveats carry forward
unchanged:

1. **The multi-actor binder is header-driven** (`X-Proof-Role`). Test-header
   trust is **unacceptable in production** — a real bank-overlay `ActorBinder`
   resolves each authenticated request from a real auth primitive (OIDC / mTLS),
   never a client header.
2. **The eager-injection wiring builds a second engine** (two engines on one
   Postgres — the eager engine backs the operator API routes, the lifespan
   engine backs boot trust-registration). Acceptable for a proof-only factory;
   **production would inject ONE engine via a real single-engine eager deploy.**
3. **The hook pack's per-pack trust root** is proof-staged (see the two-key note
   above); a production deployment provisions pack trust roots through its real
   trust-root management (per-tenant Vault-backed per ADR-012), not image-baked
   files.

These are proof-only and must NOT be shipped as kernel behavior.

## Topology / invariants (inherited from Proof M4 / 1b-2c)

* **Single effective MCP URL** `http://10.96.0.51:8765/mcp` — byte-identical
  across the **materialized** `mcp_server_url_override` row (from `configure` →
  `install`), the pack's `COGNIC_MCP_SERVER_URL` / `COGNIC_OAUTH_AUDIENCE`, the
  AgentOS-sent RFC-8707 `resource`, and the AS-echoed token `aud`. `10.96.0.51`
  is a **static private ClusterIP**, reachable ONLY via the materialized
  override + exact-IP allow-list carve-out.
* **AS issuer** `http://192.88.99.9:9000` — RFC7526 deprecated 6to4-relay-anycast:
  `is_global=True` (OAuth legs pass the hard-public-only guard) yet
  special-purpose, exposed via a Service `externalIP` kube-proxy intercepts —
  **no real egress**.
* **DLP ordering invariant** — the `dlp_pre` scan runs after the static/approval
  gates and **before** token acquisition / session open / transport send, so a
  DLP refusal never reaches the AS or the tool server (asserted by BAR 2).

## Files

| File | Purpose |
|---|---|
| `stage-packs.sh` | Downloads + **sha256-pins** + arranges BOTH released packs into `proof-m5-staging/` (wheels, per-pack attestations, the two-key trust roots, the two-pack allow-list, `alembic.ini`). |
| `proof-m5-values.yaml` | Helm overlay (proof image `cognic-agentos:proofm5`, prod profile, migrations off). |
| `migrate-job.yaml` | Non-hook migration Job (Gap-3 sidestep; `__AGENTOS_IMAGE__` sed slot). |
| `Dockerfile.agentos-proof` | Bakes the multi-actor `create_proof_app` + BOTH released packs' trust staging (incl. the hook wheel into the kernel venv) onto the default-adapters base. |
| `Dockerfile.oracle-pack` | The released oracle-schema `v0.2.0` MCP tool Service image (built from the downloaded wheel). |
| `Dockerfile.as` | The emulated-external RS256 AS image. |
| `manifests/oracle-xe.yaml` | In-cluster Oracle XE Deployment + Service (seeded via the `oracle-xe-seed` ConfigMap). |
| `manifests/oracle-pack.yaml` | Oracle-pack Deployment + Service (`clusterIP: 10.96.0.51`; real RS256/JWKS verifier). |
| `manifests/auth-server.yaml` | AS Deployment + Service (`externalIPs: [192.88.99.9]`, RS256 mode). |
| `oracle-seed/seed_schema.sql` | First-boot schema seed (single source of truth for the `oracle-xe-seed` ConfigMap). |
| `seed-db.sh` | **No-op guard** — the override + allow-list rows are **materialized by `install`**, never seeded; the hook pack needs no DB state at all. |
| `seed-vault.sh` | Provisions the OAuth + AS-allow-list secrets **by reference** (D5); hook pack needs no Vault material. |
| `run-proof-m5.sh` | The operator-run end-to-end 3-bar runner — **lands in Task 10** (not part of this scaffolding commit). |
