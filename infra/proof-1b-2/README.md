# Proof 1b-2 — Deployed Governed MCP Invocation Loop

This proof stands up a `kind` cluster and exercises the **full governed MCP
invocation path** against a deployed AgentOS kernel — `discovery_status=auth_ready`
plus real `list_tools` / `call_tool` — against an **in-cluster MCP tool Service**
reachable ONLY through the PR-2b-1 override + exact-IP allow-list carve-out, with
the OAuth legs reaching an **emulated-external (public-shaped) Authorization Server**.

It extends the Proof 1b-1 deploy harness (boot-time trust registration) with the
runtime invocation loop. The kernel is **not modified** — every artefact here is
proof-only (`infra/proof-1b-2/` + the two env-driven test/example fixtures).

## How to run (operator-only, env-gated)

```bash
COGNIC_RUN_PROOF_1B2=1 bash infra/proof-1b-2/run-proof-1b-2.sh
```

The runner is **env-gated**: with `COGNIC_RUN_PROOF_1B2` unset it prints a skip
notice and exits `0` (so it is inert in any non-operator context, including CI).
It needs `docker`, `kind`, `kubectl`, `helm`, `uv`, `cosign`, `syft`, `grype`,
`curl`, and `python3` on `PATH`. It deletes the `kind` cluster on exit (`trap`).

## What it proves

* **Bar 1 (checkpoint — prints `BAR 1 PASS`).** The PR-2b-1 carve-out is
  load-bearing. With the exact-IP allow-list row seeded, the resource leg is
  permitted (`audit.mcp_allowlist_permitted`, host `10.96.0.50`); deleting the row
  and restarting to a **cold** pod (MCPHost caches the token + tool list per
  tenant) refuses the fresh probe (`mcp_discovery_url_refused` /
  `refused_component=host_address`).
* **Bar 2 (completion — prints `PROOF 1b-2 (BAR 2) PASS`).** The full loop:
  `list_tools` 200 → `call_tool` 200 → `GET /api/v1/system/plugins?tenant_id=proof-1b-2`
  shows the `cognic-tool-search` row at `discovery_status == "auth_ready"`.

Bar 1 is a **checkpoint**, not the final pass. If Bar 2 cannot be stood up the
runner captures the pod logs + the `discovery_status` snapshot + the authz reason
to `docs/VALIDATION-RESULTS.md` and exits non-zero — the proof is **never
redefined downward**.

## Topology / invariants

* **Single effective MCP URL** `http://10.96.0.50:8765/mcp` — byte-identical across
  the `mcp_server_url_override` row, the MCP server's `COGNIC_PROOF_SERVER_URL`, the
  AgentOS-sent RFC-8707 `resource`, and the AS-echoed token `aud`. `10.96.0.50` is a
  **static private ClusterIP** (within `10.96.0.0/12`; `is_private=True`), reachable
  ONLY via the override + exact-IP allow-list carve-out — never a guard-allowed
  address.
* **AS issuer** `http://192.88.99.9:9000` — RFC7526 deprecated 6to4-relay-anycast:
  `is_global=True` (so the OAuth legs pass the hard-public-only guard with **no**
  carve-out added) yet special-purpose, exposed via a Service `externalIP` that
  kube-proxy intercepts — **no real external egress**.

## ⚠ Proof-only fixed-actor binder — production needs a real overlay

The deployed image runs a **proof-only** `create_proof_app()` factory
(`tests/integration/proof_1b_2/proof_app.py`) whose `ProofActorBinder` yields ONE
fixed `Actor` (tenant `proof-1b-2`, `actor_type="service"`, scopes EXACTLY
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
| `proof-1b-2-values.yaml` | Helm overlay (proof image `cognic-agentos:proof1b2`, prod profile, migrations off). |
| `migrate-job.yaml` | Non-hook migration Job (Gap-3 sidestep; `__AGENTOS_IMAGE__` sed slot). |
| `Dockerfile.agentos-proof` | Bakes `create_proof_app` + the 1b-1 trust staging onto the default-adapters base. |
| `Dockerfile.mcp-server` | The private-ClusterIP MCP tool Service image. |
| `Dockerfile.as` | The emulated-external AS image. |
| `manifests/mcp-server.yaml` | MCP Deployment + Service (`clusterIP: 10.96.0.50`). |
| `manifests/auth-server.yaml` | AS Deployment + Service (`externalIPs: [192.88.99.9]`). |
| `seed-db.sh` | Seeds the override + exact-IP allow-list rows in Postgres. |
| `seed-vault.sh` | Converts `secret/` to KV v1 + seeds the OAuth + AS-allow-list secrets. |
| `run-proof-1b-2.sh` | The operator-run end-to-end runner (Bar 1 → Bar 2). |
