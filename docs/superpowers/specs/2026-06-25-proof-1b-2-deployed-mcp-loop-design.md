# Proof 1b-2 — Deployed Governed MCP Invocation Loop — Design

**Status:** design approved 2026-06-25; spec for review before the implementation plan.

**Goal:** Prove, in a `kind` cluster, that a deployed AgentOS kernel performs the full **governed MCP invocation path** — `discovery_status=auth_ready` + a real `list_tools` / `call_tool` — against an in-cluster MCP tool Service reachable **only** through the PR-2b-1 operator `server_url` override + per-tenant exact-IP internal-host allow-list, with the OAuth token legs reaching an emulated-external (public-shaped) Authorization Server.

## Background

PR-2b-1 (merged to `main` @ `9f157ca`) added the operator override + exact-IP allow-list stores + the SSRF-guard carve-out for the 3 MCP **resource** legs (`server_url` / `prm_metadata` / `well_known_prm`), HTTP-only, while the OAuth legs (`as_metadata` / `token_endpoint`) stay hard-public-only (PR-2b-0). The deployed-proof axis (Proof 1b-1) established boot-time trust registration of a signed pack via image-bake / mounted-volume (there is no runtime install API). **Proof 1b-2 builds on that registration and proves the invoke path the override + allow-list make reachable.**

The substrate block that stalled Proof 1b-1 is resolved on `main` (#98 @ `cfff453`: the image packages `policies/` + `alembic.ini`; the migration Job gets `envFrom` the ConfigMap). The **default-adapters** image carries the `mcp` SDK and runs `create_prod_app`, so a deployed kernel serves MCP; the bare kernel image does not — **the proof pins the default-adapters image**.

## Staged bars

**Bar 1 — carve-out checkpoint (required, NOT completion).** The override + allow-list let the **resource** legs reach the private in-cluster MCP ClusterIP where the bare strict guard refuses, emitting `audit.mcp_allowlist_permitted`. This proves PR-2b-1 itself in a deployed kernel. Bar 1 passing is a checkpoint — it is **not** "Proof 1b-2 complete."

**Bar 2 — Proof 1b-2 completion.** The full governed loop: `discovery_status=auth_ready` (resource legs used the carve-out; OAuth legs stayed public and completed the token-acquire) + a real `list_tools` and `call_tool` against the override-pinned ClusterIP. This is the bar that means "deployed AgentOS performs the governed MCP invocation path." **If Bar 2's topology proves too awkward to stand up, that is recorded as a design/product finding — never a reason to redefine Proof 1b-2 downward.**

## Topology (kind)

- **AgentOS** — default-adapters image, `runtimeProfile: prod` (strict SSRF guard live). DB pre-seeded (G1 — **direct seed, not an operator-API surface in this proof**): the override row `(tenant, pack)` → the MCP ClusterIP URL; the allow-list row (the MCP ClusterIP); Vault OAuth client credentials for `(tenant, AS-issuer)`. The `cognic-tool-search` pack is boot-time trust-registered (the Proof 1b-1 mechanism).
- **MCP tool Service** (G2) — a tiny image from the `examples/cognic-tool-search` FastMCP server (edits: bind `0.0.0.0`; env-drive the advertised URL to the ClusterIP). **Private ClusterIP.** Serves `/mcp` (Streamable HTTP), returns 401 + PRM at `/.well-known/oauth-protected-resource/mcp` advertising the AS issuer.
- **Authorization Server** (emulated-external) — a tiny image from `tests/integration/pack_loop/_local_as.py` (client-credentials AS; echoes the RFC-8707 `resource` into the token `aud`). Exposed at a **guard-allowed genuine-global Service `externalIP`**, kube-proxy-intercepted in-cluster. The MCP Service stays private; only the AS wears the public-shaped address.

**Network model.** The AS `externalIP` is a genuine-global IP (a clearly-labeled stand-in); kube-proxy DNATs in-cluster traffic destined for it onto the AS pod, so **there is no real external egress** — the "public" address never leaves the cluster. Chosen over CGNAT (`100.64.0.0/10`) because it matches the guard's intended public/private model and avoids Python-version fragility in `ipaddress.is_private`.

## The governed flow (one clean invocation)

1. The override resolves the registered pack's `server_url` → the MCP ClusterIP URL (the signed manifest URL is never mutated; the override is read at use).
2. `server_url` leg → MCP ClusterIP — **resource leg, carved out** (allow-listed private IP, HTTP-only) → 401 + PRM.
3. `prm_metadata` (+ `well_known_prm`) leg → MCP ClusterIP — **resource leg, carved out** → the PRM advertises the AS issuer (public-shaped).
4. `as_metadata` + `token_endpoint` legs → AS issuer — **OAuth legs, guard-allowed because the AS is public-shaped** → token acquired (RFC-8707 `resource` = the ClusterIP URL; `aud` = the ClusterIP URL).
5. Audience validation passes (`aud == effective_server_url`) → token cached → `discovery_status=auth_ready`.
6. `list_tools` + `call_tool` → the override-pinned ClusterIP (resource leg, carved out) with the bearer → real tool result.

## Invariants (recorded explicitly)

- **No real external egress.** The "public" AS IP is kube-proxy-intercepted inside kind; nothing leaves the cluster.
- **The MCP Service remains a private ClusterIP.** Its reachability is **only** via the PR-2b-1 override + allow-list carve-out — never a public / guard-allowed address (that would defeat the carve-out proof).
- **Single effective MCP URL.** The same value must appear in the override row, the RFC-8707 `resource` form param, the token `aud`, and the MCP server's advertised `_SERVER_URL` / PRM `resource`. A mismatch fails audience validation.
- **OAuth legs stay hard-public-only.** No carve-out is added to `as_metadata` / `token_endpoint`; PR-2b-0 is intact. `auth_ready` is earned by the AS genuinely being public-shaped, not by weakening the guard.

## Findings to record (in `docs/VALIDATION-RESULTS.md`, regardless of outcome)

- **F1 — no guard-allowed documentation range.** RFC5737 (`192.0.2/198.51.100/203.0.113`), RFC2544 (`198.18/15`), and reserved (`240/4`) are all `is_private` / `is_reserved` → SSRF-refused; only genuine-global (or CGNAT) addresses pass the guard. Emulating an external AS in an all-private kind cluster therefore requires a genuine-global stand-in + kube-proxy interception. This is a **proof-design wrinkle, not a kernel defect.**
- **F2 — CGNAT/public classification.** `ipaddress` classifies `100.64.0.0/10` (RFC6598 CGNAT) as `is_private=False` on this CPython, so the guard treats it as public — a latent SSRF nuance worth a tracked note, **separate from and not part of** Proof 1b-2.

## Success criteria

- **Bar 1:** with the override + allow-list seeded, a deployed-kernel resource-leg fetch reaches the private MCP ClusterIP and emits exactly one `audit.mcp_allowlist_permitted` event; with the allow-list row removed, the same fetch is SSRF-refused (`mcp_discovery_url_refused`, `refused_component=host_address`). **The delta is the carve-out.**
- **Bar 2:** the discovery-status surface (`GET /api/v1/system/plugins`, `?tenant_id=`) shows `discovery_status=auth_ready` for the `(tenant, pack)`; a `list_tools` returns the server's tool set; a `call_tool` returns a real result — all against the override-pinned private ClusterIP, prod profile, OAuth legs public.

## Out of scope

- Turning `create_prod_app` into an operator override/allow-list API surface (G1 uses a direct DB seed; the prod router-mount restructure is a separate decision).
- Fixing F2 (the CGNAT classification) in the kernel.
- Multi-tenant / multi-pack; failure-injection beyond the Bar 1 allow-list-removed delta.

## Open plan-level details (the implementation plan pins these)

- The exact `(tenant_id, pack_id)` keys + the boot-time registration staging (reuse the Proof 1b-1 `feat/pack-loop-proof-1b` harness @ `2125b22` and its `infra/proof-1b/` staging tree).
- The Vault path + shape for the `(tenant, AS-issuer)` OAuth client credentials, and the per-tenant AS allow-list entry (the `mcp_as_not_allowlisted` gate at `acquire_token` step 3).
- The MCP server + AS image builds (Dockerfiles, the `0.0.0.0` / URL-env edits), the exact genuine-global `externalIP`, and the Service/Deployment manifests.
- Whether the proof runs as an env-gated `kind` job (mirroring the existing `kind-smoke`) or an operator-run script; and the Bar 1 → Bar 2 sequencing within one cluster bring-up.
