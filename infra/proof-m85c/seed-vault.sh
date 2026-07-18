#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proofm85c}"; T="proof-m85c"; ASHOST="192.88.99.9_9000"; AS="http://192.88.99.9:9000"
: "${ORACLE_APP_PASSWORD:?ORACLE_APP_PASSWORD must be supplied by the proof runner}"
# KEPT from proof-m4/m5/m6 (ADR-026 D5 — OAuth material provisioned BY REFERENCE):
# the operator pre-provisions the OAuth client + AS allow-list in Vault; the
# M4-flow `configure` step then records those Vault PATHS (oauth_credential_ref /
# as_allowlist_ref) on the desired runtime-config record for the v0.5.0 tool pack,
# and `install`'s materializer VALIDATES they resolve + are well-shaped BEFORE it
# projects the derived carve-out rows. There is NO secret-write API — the operator
# seeds Vault out of band (this script). Neither the hook pack nor the four
# instruction-skill packs nor the agent pack needs Vault material: hooks are
# in-process kernel code; instruction skills are CONTENT (hosted, never
# executed); the agent's tool calls acquire OAuth material KERNEL-side through
# the dispatcher -> MCPHost path, from these same by-reference seeds. The M8
# query-context keypair is NOT Vault material in this proof — it rides a k8s
# Secret mount (see run-proof-m85c.sh + agentos-sandbox-patch.yaml; vault://
# resolution is the named A13 follow-up).
#
# VAULT_TOKEN = the reused backends.yaml Vault dev root token (VAULT_DEV_ROOT_TOKEN_ID=smoke-root-token);
# must equal proof-m85c-values.yaml secrets.vaultToken (else `vault` 403s).
VX() { kubectl -n "$NS" exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=smoke-root-token vault "$@"; }
VX secrets disable secret || true
VX secrets enable -version=1 -path=secret kv
# mcp-as-allowlist.servers MUST be a JSON LIST — _load_as_allowlist (mcp_authz.py) expects a list.
# `vault kv put key=value` stores a STRING; use Vault's reliable @file JSON form (a bare `-` may be parsed
# as a data arg, not stdin). Write the JSON to a temp file INSIDE the vault pod, then feed it via @file.
# TRAILING SLASH: the MCP server (FastMCP) wraps the AS issuer in pydantic AnyHttpUrl, which normalises
# "http://h:9000" -> "http://h:9000/", so its PRM advertises authorization_servers as ["${AS}/"]. The kernel
# compares the PRM-advertised issuer against this allow-list by EXACT string (RFC 8414 issuer semantics —
# mcp_authz.py `s in allowed_servers`), so the seeded entry MUST carry the same trailing slash or the
# carve-out refuses with mcp_as_not_allowlisted.
echo "{\"servers\":[\"${AS}/\"]}" | kubectl -n "$NS" exec -i deploy/vault -- sh -c 'cat > /tmp/as-allowlist.json'
VX kv put "secret/cognic/$T/mcp-as-allowlist" @/tmp/as-allowlist.json
# readback assertion: servers must come back as a JSON ARRAY (KV v1 -> data.servers)
VX kv get -format=json "secret/cognic/$T/mcp-as-allowlist" | python3 -c 'import json,sys; s=json.load(sys.stdin)["data"]["servers"]; assert isinstance(s,list), f"servers not a list: {type(s).__name__}"; print("as-allowlist OK:", s)'
VX kv put "secret/cognic/$T/mcp-oauth/$ASHOST" client_id=proof-client client_secret=proof-secret auth_method=client_secret_post

# D3: the per-run Oracle application credential enters Vault over stdin. Its
# bytes never appear in argv or output, and the readback asserts shape only.
printf '%s' "$ORACLE_APP_PASSWORD" | kubectl -n "$NS" exec -i deploy/vault -- \
  env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=smoke-root-token \
  vault kv put "secret/cognic/$T/oracle-app" password=-
VX kv get -format=json "secret/cognic/$T/oracle-app" | python3 -c 'import json,sys; p=json.load(sys.stdin)["data"]["password"]; assert isinstance(p, str) and p; print("oracle app credential OK: present")'

# M8 finding #6 (2026-07-07): the LiteLLM router (litellm pod) enforces its dev
# master key; under the prod profile the kernel refuses a PLAINTEXT
# litellm_master_key (config.py secret_plain_value_forbidden_in_strict_profile),
# so the kernel resolves it by-reference: COGNIC_LITELLM_MASTER_KEY=vault://
# secret/cognic/proof-m85c/litellm (run-proof-m85c.sh step 8). The field name MUST
# be "key" — resolve_secret_field reads payload["key"] (db/adapters/
# secret_resolution.py _SECRET_VALUE_KEY). The VALUE must equal the litellm
# pod's own LITELLM_MASTER_KEY (dev-only-litellm) so the gateway authenticates.
VX kv put "secret/cognic/$T/litellm" key=dev-only-litellm
# readback assertion (KV v1 -> data.key): the kernel's build_runtime resolves
# THIS at lifespan; a wrong field/path would fail the pod boot loud.
VX kv get -format=json "secret/cognic/$T/litellm" | python3 -c 'import json,sys; k=json.load(sys.stdin)["data"]["key"]; assert k=="dev-only-litellm", f"litellm key mismatch: {k!r}"; print("litellm master key OK")'
