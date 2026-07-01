# Proof M4 — Operator-Grade Pack Install Flow (deployed, API-driven)

This proof stands up a `kind` cluster and exercises the **full governed
operator-install lifecycle** against a deployed AgentOS kernel — `submit → claim
→ approve → allow-list → configure → install`, then `disable` / `revoke` — using
the **RELEASED, signed `cognic-tool-oracle-schema@v0.1.0`** pack, an **in-cluster
Oracle XE** backing the pack's read-only schema-metadata tools, and an
**emulated-external (public-shaped) RS256 Authorization Server**.

It **extends** the proven Proof 1b-2c runner: same released pack, same Oracle XE +
RS256/JWKS AS, same single-effective MCP URL (`10.96.0.51:8765/mcp`). The **delta
is the seeding** — proof-1b-2c `INSERT`ed the `mcp_server_url_override` +
`mcp_internal_host_allowlist` carve-out rows directly; **M4 removes that** and
drives the **real operator API** instead. `install`'s materializer **materializes**
those derived rows from the DESIRED runtime-config record (`configure` writes it);
`disable` / `revoke` **retract** them. `mcp_authz` is **unchanged** — it reads the
derived rows exactly as today (M4 safety property D6).

The kernel is **not modified** — every artefact here is proof-only
(`infra/proof-m4/` + the test fixtures under `tests/integration/proof_m4/`).

## What's different from Proof 1b-2c

* **No direct override/allow-list seeding.** `seed-db.sh` is a **no-op guard** (it
  fail-loud-refuses if a future edit re-introduces the derived-row `INSERT`s). The
  override + allow-list rows exist **only** because `install` materialized them
  from the configured runtime-config record.
* **Multi-actor, API-driven lifecycle.** The runner drives the real operator API
  with **four distinct actors** (author / reviewer / operator / MCP caller),
  selected via the `X-Proof-Role` request header
  (`tests/integration/proof_m4/proof_app.py::MultiActorProofBinder`). The reviewer
  subject is deliberately **different** from the author so the role-separation
  guard (`RequireDifferentActorThanCreator`) passes.
* **5-gate approve with a REAL signature gate.** The proof app threads a real
  `TrustGate` + a proof-only staged `TrustRootResolver`, so the approve
  composition's **signature gate cosign-verifies the released, signed pack**
  against the staged `_default` trust root. The four **non-signature** gates
  (evaluation / adversarial / OWASP / reviewer-ack) are cleared via the
  **override path** (the reviewer role holds `pack.override.approval_gate`).
  Signature is **non-overridable** (ADR-012 §110) — BAR 2 proves a signature-red
  pack is refused approve even with an override reason.

## How to run (operator-only, env-gated)

```bash
COGNIC_RUN_PROOF_M4=1 bash infra/proof-m4/run-proof-m4.sh
```

The runner is **env-gated**: with `COGNIC_RUN_PROOF_M4` unset it prints a skip
notice and exits `0` (inert in any non-operator context, including CI). It needs
`docker`, `kind`, `kubectl`, `helm`, `uv`, `cosign`, `syft`, `grype`, `curl`,
`python3`, and `gh` on `PATH`. It deletes the `kind` cluster on exit (`trap`).

## What it proves

* **BAR 1 (happy — prints `PROOF M4 (BAR 1) PASS`).** The full operator lifecycle
  via the API materializes the override + allow-list rows (asserted via the
  `decision_history` events `mcp.override.set` + `mcp.allowlist.add`) → a cold pod
  boots → `discovery_status=auth_ready` → `call_tool(describe_table owner=COGNIC
  table=EMPLOYEES)` returns the seeded `EMPLOYEES` column `FULL_NAME`.
* **BAR 2 (negatives — prints `PROOF M4 (BAR 2) PASS`).** `install` refused when
  not approved/allow-listed (gate 1, `lifecycle_transition_invalid_state_pair`),
  when not configured (gate 3, `install_runtime_config_missing`), and when the
  Vault OAuth ref is absent (gate 4, `install_runtime_config_vault_ref_unresolved`);
  `approve` refused **412** on a signature-red pack (signature stays REAL,
  non-overridable). Each via the API, asserting the closed-enum reason.
* **BAR 3 (disable/revoke — prints `PROOF M4 (BAR 3) PASS`).** Post-install
  `disable` retracts the derived rows → a cold probe is `discovery_status=refused`;
  re-`install` (the `disabled → installed` re-enable) re-materializes → callable
  again; `revoke` retracts + is terminal → `discovery_status=refused` +
  install-after-revoke `409`.

On any BAR failure the runner captures pod logs + the `discovery_status` snapshot
+ the last API response + the `decision_history` tail to `docs/VALIDATION-RESULTS.md`
and exits non-zero — the proof is **never redefined downward**.

## ⚠ Proof-only wiring — production needs a real overlay

The deployed image runs a **proof-only** `create_proof_app()` factory
(`tests/integration/proof_m4/proof_app.py`). Two pieces are proof-only:

1. **The multi-actor binder is header-driven.** `MultiActorProofBinder` picks the
   role `Actor` from the `X-Proof-Role` request header. Test-header trust is
   **unacceptable in production** — a real bank-overlay `ActorBinder` resolves each
   authenticated request to a genuine `Actor` from a real auth primitive
   (OIDC / mTLS), never a client header.
2. **The eager-injection wiring builds a second engine (the two-engine note).**
   The packs router (author + review + operator) and the configure router mount at
   `create_app` **body** time from kwargs whose stores need a live engine — but
   `create_app` builds its adapter engine in the **lifespan**. So the factory
   builds an **eager** `AsyncEngine` from `settings.database_url` + the operator
   stores + the materializer + the trust gate and passes them as kwargs; the
   lifespan still builds the runtime / MCP host / **boot registry** on its **own**
   engine (the SAME Postgres via the same `COGNIC_*` DB URL). Two engines on one DB
   is acceptable for a **proof-only** factory (the eager engine backs the operator
   API routes; the lifespan engine backs the boot trust-registration that install
   gate 2 reads from `app.state.plugin_registry` at request time, ADR-026 D6).
   **Production would inject ONE engine via a real single-engine eager deploy.**

These are proof-only and must NOT be shipped as kernel behavior.

## Topology / invariants (inherited from Proof 1b-2c)

* **Single effective MCP URL** `http://10.96.0.51:8765/mcp` — byte-identical
  across the **materialized** `mcp_server_url_override` row (from `configure` →
  `install`), the pack's `COGNIC_MCP_SERVER_URL` / `COGNIC_OAUTH_AUDIENCE`, the
  AgentOS-sent RFC-8707 `resource`, and the AS-echoed token `aud`. `10.96.0.51` is
  a **static private ClusterIP**, reachable ONLY via the materialized override +
  exact-IP allow-list carve-out.
* **AS issuer** `http://192.88.99.9:9000` — RFC7526 deprecated 6to4-relay-anycast:
  `is_global=True` (OAuth legs pass the hard-public-only guard) yet special-purpose,
  exposed via a Service `externalIP` kube-proxy intercepts — **no real egress**.

## Files

| File | Purpose |
|---|---|
| `proof-m4-values.yaml` | Helm overlay (proof image `cognic-agentos:proofm4`, prod profile, migrations off). |
| `migrate-job.yaml` | Non-hook migration Job (Gap-3 sidestep; `__AGENTOS_IMAGE__` sed slot). |
| `Dockerfile.agentos-proof` | Bakes the **multi-actor** `create_proof_app` + the released trust staging onto the default-adapters base. |
| `Dockerfile.oracle-pack` | The released oracle-schema MCP tool Service image (built from the downloaded wheel). |
| `Dockerfile.as` | The emulated-external RS256 AS image. |
| `manifests/oracle-xe.yaml` | In-cluster Oracle XE Deployment + Service (seeded via the `oracle-xe-seed` ConfigMap). |
| `manifests/oracle-pack.yaml` | Oracle-pack Deployment + Service (`clusterIP: 10.96.0.51`; real RS256/JWKS verifier). |
| `manifests/auth-server.yaml` | AS Deployment + Service (`externalIPs: [192.88.99.9]`, RS256 mode). |
| `oracle-seed/seed_schema.sql` | First-boot schema seed (single source of truth for the `oracle-xe-seed` ConfigMap). |
| `seed-db.sh` | **No-op guard** — the override + allow-list rows are **materialized by `install`**, never seeded. |
| `seed-vault.sh` | Provisions the OAuth + AS-allow-list secrets **by reference** (D5). |
| `run-proof-m4.sh` | The operator-run end-to-end runner (BAR 1 happy → BAR 2 negatives → BAR 3 disable/revoke). |
