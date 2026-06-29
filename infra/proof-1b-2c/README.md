# Proof 1b-2c (M3-E2c) — Deployed Governed MCP Loop Against the Released Oracle Pack

This proof stands up a `kind` cluster and exercises the **full governed MCP
invocation path** against a deployed AgentOS kernel — `discovery_status=auth_ready`
plus real `list_tools` / `call_tool` — using the **RELEASED, signed
`cognic-tool-oracle-schema@v0.1.0`** pack (the first pack of the RM-Copilot suite),
an **in-cluster Oracle XE** backing the pack's read-only schema-metadata tools, and
an **emulated-external (public-shaped) RS256 Authorization Server**.

It ADAPTS the proven Proof 1b-2 runner with the M3-E2c deltas. The kernel is **not
modified** — every artefact here is proof-only (`infra/proof-1b-2c/` + the two
env-driven test fixtures under `tests/integration/proof_1b_2c/`).

## What's different from Proof 1b-2

* **Released artifact, not a local build.** The pack wheel + its 7 attestations +
  `cosign.pub` are **downloaded** from the `v0.1.0` GitHub release and **sha256-verified**
  by `tests/integration/proof_1b_2c/stage_released_pack.py` (acceptance criterion #1) —
  there is **no** `uv build`.
* **In-cluster Oracle XE.** `gvenzl/oracle-xe:21-slim` is seeded once on first boot
  from `oracle-seed/seed_schema.sql` (the single source of truth — the runner builds the
  `oracle-xe-seed` ConfigMap straight from that file). The seed creates `COGNIC.DEPARTMENTS`
  + `COGNIC.EMPLOYEES` so the pack's tools return real metadata.
* **RS256 AS.** The AS runs with `COGNIC_PROOF_AS_SIGNING_MODE=rs256` and serves JWKS, so
  the released pack's **real** `PyJWKClient` / RS256 verifier verifies the token (the 1b-2
  example accepted any bearer).

## How to run (operator-only, env-gated)

```bash
COGNIC_RUN_PROOF_1B2C=1 bash infra/proof-1b-2c/run-proof-1b-2c.sh
```

The runner is **env-gated**: with `COGNIC_RUN_PROOF_1B2C` unset it prints a skip
notice and exits `0` (so it is inert in any non-operator context, including CI).
It needs `docker`, `kind`, `kubectl`, `helm`, `uv`, `cosign`, `syft`, `grype`,
`curl`, `python3`, and `gh` on `PATH`. It deletes the `kind` cluster on exit (`trap`).

### Optional verifier negative (off by default)

```bash
COGNIC_RUN_PROOF_1B2C=1 COGNIC_PROOF_VERIFIER_NEGATIVE=1 bash infra/proof-1b-2c/run-proof-1b-2c.sh
```

After Bar 2, this points the pack's expected audience at a non-matching URL and proves
`call_tool` **fails** because the pack's real RS256 verifier rejects the `aud` mismatch,
then reverts. It is kept off the main run so the happy path stays lean.

## What it proves

* **Bar 1 (checkpoint — prints `BAR 1 PASS`).** The PR-2b-1 carve-out is
  load-bearing. With the exact-IP allow-list row seeded, the resource leg is
  permitted (`audit.mcp_allowlist_permitted`, host `10.96.0.51`); deleting the row
  and restarting to a **cold** pod (MCPHost caches the token + tool list per
  tenant) refuses the fresh probe (`mcp_discovery_url_refused` /
  `discovery_status=refused`).
* **Bar 2 (completion — prints `PROOF 1b-2c (BAR 2) PASS`).** The full loop:
  `list_tools` 200 → `call_tool` `describe_table(owner=COGNIC, table=EMPLOYEES)` 200
  carrying the seeded `EMPLOYEES` column metadata → `GET
  /api/v1/system/plugins?tenant_id=proof-1b-2c` shows the `cognic-tool-oracle-schema`
  row at `discovery_status == "auth_ready"`.

Bar 1 is a **checkpoint**, not the final pass. If Bar 2 cannot be stood up the
runner captures the pod logs + the `discovery_status` snapshot + the authz reason
to `docs/VALIDATION-RESULTS.md` and exits non-zero — the proof is **never
redefined downward**.

## Topology / invariants

* **Single effective MCP URL** `http://10.96.0.51:8765/mcp` — byte-identical across
  the `mcp_server_url_override` row, the pack's `COGNIC_MCP_SERVER_URL` /
  `COGNIC_OAUTH_AUDIENCE`, the AgentOS-sent RFC-8707 `resource`, and the AS-echoed token
  `aud`. `10.96.0.51` is a **static private ClusterIP** (within `10.96.0.0/12`;
  `is_private=True`), reachable ONLY via the override + exact-IP allow-list carve-out —
  never a guard-allowed address.
* **AS issuer** `http://192.88.99.9:9000` — RFC7526 deprecated 6to4-relay-anycast:
  `is_global=True` (so the OAuth legs pass the hard-public-only guard with **no**
  carve-out added) yet special-purpose, exposed via a Service `externalIP` that
  kube-proxy intercepts — **no real external egress**.

## ⚠ Proof-only fixed-actor binder — production needs a real overlay

The deployed image runs a **proof-only** `create_proof_app()` factory
(`tests/integration/proof_1b_2c/proof_app.py`) whose `ProofActorBinder` yields ONE
fixed `Actor` (tenant `proof-1b-2c`, `actor_type="service"`, scopes EXACTLY
`{"mcp.tool.list", "mcp.tool.invoke"}`) so the governed MCP invoke route
(`/api/v1/mcp/...`) can be driven end-to-end without an identity provider. It calls
the normal `create_app(...)` and only sets `app.state.actor_binder`; it does **not**
fork runtime behavior.

**This binder is proof-only. Production still requires a real
bank-overlay ActorBinder** (OIDC / mTLS-backed) that resolves each authenticated
request to a genuine `Actor` — it is NOT part of the kernel and must NOT be shipped
as one.

## Files

| File | Purpose |
|---|---|
| `proof-1b-2c-values.yaml` | Helm overlay (proof image `cognic-agentos:proof1b2c`, prod profile, migrations off). |
| `migrate-job.yaml` | Non-hook migration Job (Gap-3 sidestep; `__AGENTOS_IMAGE__` sed slot). |
| `Dockerfile.agentos-proof` | Bakes `create_proof_app` + the released trust staging onto the default-adapters base. |
| `Dockerfile.oracle-pack` | The released oracle-schema MCP tool Service image (built from the downloaded wheel). |
| `Dockerfile.as` | The emulated-external RS256 AS image. |
| `manifests/oracle-xe.yaml` | In-cluster Oracle XE Deployment + Service (seeded via the `oracle-xe-seed` ConfigMap). |
| `manifests/oracle-pack.yaml` | Oracle-pack Deployment + Service (`clusterIP: 10.96.0.51`; real RS256/JWKS verifier). |
| `manifests/auth-server.yaml` | AS Deployment + Service (`externalIPs: [192.88.99.9]`, RS256 mode). |
| `oracle-seed/seed_schema.sql` | First-boot schema seed (single source of truth for the `oracle-xe-seed` ConfigMap). |
| `seed-db.sh` | Seeds the override + exact-IP allow-list rows in Postgres. |
| `seed-vault.sh` | Converts `secret/` to KV v1 + seeds the OAuth + AS-allow-list secrets. |
| `run-proof-1b-2c.sh` | The operator-run end-to-end runner (Bar 1 → Bar 2 → optional verifier negative). |
