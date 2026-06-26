#!/usr/bin/env bash
set -euo pipefail
NS="${NS:-cognic-proof1b2}"; T="proof-1b-2"; ASHOST="192.88.99.9_9000"; AS="http://192.88.99.9:9000"
# VAULT_TOKEN = the reused backends.yaml Vault dev root token (VAULT_DEV_ROOT_TOKEN_ID=smoke-root-token);
# pinned == proof-1b-2-values.yaml vaultToken by tests/unit/proof_1b_2/test_proof_seeds.py (else `vault` 403s).
VX() { kubectl -n "$NS" exec deploy/vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=smoke-root-token vault "$@"; }
VX secrets disable secret || true
VX secrets enable -version=1 -path=secret kv
# mcp-as-allowlist.servers MUST be a JSON LIST — _load_as_allowlist (mcp_authz.py:1439) expects a list.
# `vault kv put key=value` stores a STRING; use Vault's reliable @file JSON form (a bare `-` may be parsed
# as a data arg, not stdin). Write the JSON to a temp file INSIDE the vault pod, then feed it via @file.
# TRAILING SLASH: the MCP server (FastMCP) wraps the AS issuer in pydantic AnyHttpUrl, which normalises
# "http://h:9000" -> "http://h:9000/", so its PRM advertises authorization_servers as ["${AS}/"]. The kernel
# compares the PRM-advertised issuer against this allow-list by EXACT string (RFC 8414 issuer semantics —
# mcp_authz.py:753 `s in allowed_servers`), so the seeded entry MUST carry the same trailing slash or the
# carve-out refuses with mcp_as_not_allowlisted (Proof 1b-2 attempt-4 finding).
echo "{\"servers\":[\"${AS}/\"]}" | kubectl -n "$NS" exec -i deploy/vault -- sh -c 'cat > /tmp/as-allowlist.json'
VX kv put "secret/cognic/$T/mcp-as-allowlist" @/tmp/as-allowlist.json
# readback assertion: servers must come back as a JSON ARRAY (KV v1 -> data.servers)
VX kv get -format=json "secret/cognic/$T/mcp-as-allowlist" | python3 -c 'import json,sys; s=json.load(sys.stdin)["data"]["servers"]; assert isinstance(s,list), f"servers not a list: {type(s).__name__}"; print("as-allowlist OK:", s)'
VX kv put "secret/cognic/$T/mcp-oauth/$ASHOST" client_id=proof-client client_secret=proof-secret auth_method=client_secret_post
