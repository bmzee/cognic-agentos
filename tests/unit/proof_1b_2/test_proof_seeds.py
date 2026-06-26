"""Structural gate (author-time): the Proof 1b-2 seed scripts pin the
load-bearing seed values + the Vault KV-v1 JSON-list shape OFFLINE — without a
``kind`` cluster, ``kubectl``, ``psql``, or any ``vault`` call (the scripts RUN
only at the operator-run T9 stage, gated behind ``COGNIC_RUN_PROOF_1B2=1``).

Per the Proof 1b-2 plan (Task 8), the two scripts under ``infra/proof-1b-2/``
seed the deployed governed MCP loop's data plane:

* ``seed-db.sh`` inserts the PR-2b-1 carve-out rows into Postgres — the
  ``mcp_server_url_override`` row (the single effective MCP URL
  ``http://10.96.0.50:8765/mcp``) + the ``mcp_internal_host_allowlist`` row (the
  exact private ClusterIP ``10.96.0.50``). Together they make the private MCP
  Service reachable via the override + exact-IP allow-list and ONLY that way.
* ``seed-vault.sh`` converts the dev ``secret/`` mount to **KV v1** (the bundled
  adapter does a raw ``transport.read(path)`` with no ``/data/`` segment), then
  seeds the OAuth client secret + the AS allow-list. The AS allow-list
  ``servers`` field MUST be a JSON **list** — ``_load_as_allowlist``
  (``mcp_authz.py``) expects a list, and ``vault kv put key=value`` would store a
  **string**. The script therefore writes the JSON via Vault's ``@file`` form
  (``@/tmp/as-allowlist.json``), NEVER the inline ``servers=`` key=value form.

Every value below is byte-identical to the plan's Global Constraints — the
override row / allow-list seed / RFC-8707 ``resource`` / token ``aud`` / AS
``issuer`` alignment all depend on it. A drifted seed value would silently break
the deployed loop; these tests catch it at author time. They read both scripts as
text only — they never invoke ``kubectl`` / ``psql`` / ``vault`` / a cluster.
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SEED_DIR = _REPO_ROOT / "infra" / "proof-1b-2"
_SEED_DB = _SEED_DIR / "seed-db.sh"
_SEED_VAULT = _SEED_DIR / "seed-vault.sh"

# Global-Constraints invariant values — byte-identical across the override row /
# allow-list seed / Vault AS allow-list / Vault path segment / container env.
_PROOF_TENANT = "proof-1b-2"
_MCP_SERVER_URL = "http://10.96.0.50:8765/mcp"
_MCP_ALLOWLIST_IP = "10.96.0.50"
_AS_ISSUER = "http://192.88.99.9:9000"
_AS_HOST_SEGMENT = "192.88.99.9_9000"


def _db_text() -> str:
    return _SEED_DB.read_text()


def _vault_text() -> str:
    return _SEED_VAULT.read_text()


def test_seed_scripts_exist() -> None:
    assert _SEED_DB.is_file(), f"Proof 1b-2 DB seed script not found at {_SEED_DB}"
    assert _SEED_VAULT.is_file(), f"Proof 1b-2 Vault seed script not found at {_SEED_VAULT}"


def test_scripts_are_strict_bash() -> None:
    # `set -euo pipefail` is load-bearing: a failed seed step (psql error, vault
    # error, the readback assertion) MUST abort the script, not silently continue.
    for text, name in ((_db_text(), "seed-db.sh"), (_vault_text(), "seed-vault.sh")):
        assert text.startswith("#!/usr/bin/env bash"), f"{name} must start with the bash shebang"
        assert "set -euo pipefail" in text, f"{name} must `set -euo pipefail`"


# --- seed-db.sh: the PR-2b-1 carve-out rows -------------------------------------


def test_db_seed_tenant_is_the_proof_tenant() -> None:
    # The tenant scopes BOTH the override row and the allow-list row; it must match
    # the proof-only binder's fixed tenant (proof_app.PROOF_TENANT) byte-for-byte.
    assert f'T="{_PROOF_TENANT}"' in _db_text()


def test_db_seed_overrides_the_single_effective_mcp_url() -> None:
    # The override row's server_url_override is the single effective MCP URL — it
    # must be byte-identical to the MCP container's COGNIC_PROOF_SERVER_URL, the
    # AgentOS-sent RFC-8707 resource, and the AS-echoed token aud.
    assert f'URL="{_MCP_SERVER_URL}"' in _db_text()


def test_db_seed_allow_lists_the_exact_private_cluster_ip() -> None:
    # The exact-IP allow-list row seeds THIS private ClusterIP; the carve-out
    # permits the override URL's host only because this row is present.
    assert f'IP="{_MCP_ALLOWLIST_IP}"' in _db_text()


def test_db_seed_targets_the_two_pr_2b_1_tables() -> None:
    # The override + allow-list rows land in the two PR-2b-1 tables. Drift in either
    # table name = an INSERT into a non-existent table (ON_ERROR_STOP=1 aborts).
    text = _db_text()
    assert "mcp_server_url_override" in text, "must INSERT into mcp_server_url_override"
    assert "mcp_internal_host_allowlist" in text, "must INSERT into mcp_internal_host_allowlist"


# --- seed-vault.sh: KV-v1 conversion + the JSON-list AS allow-list ---------------


def test_vault_seed_tenant_is_the_proof_tenant() -> None:
    assert f'T="{_PROOF_TENANT}"' in _vault_text()


def test_vault_seed_carries_the_as_issuer_and_path_segment() -> None:
    # AS = the issuer (Vault mcp-as-allowlist servers[0]); ASHOST = the per-AS Vault
    # path segment (secret/cognic/<T>/mcp-oauth/<ASHOST>). Both byte-identical to
    # the AS container's COGNIC_PROOF_AS_ISSUER.
    text = _vault_text()
    assert f'AS="{_AS_ISSUER}"' in text
    assert f'ASHOST="{_AS_HOST_SEGMENT}"' in text


def test_vault_seed_re_enables_secret_mount_as_kv_v1() -> None:
    # The dev secret/ mount defaults to KV v2; the bundled SecretAdapter does a raw
    # transport.read(path) with NO /data/ segment, so the mount MUST be KV v1.
    assert "secrets enable -version=1 -path=secret kv" in _vault_text()


def test_vault_seed_writes_as_allowlist_via_json_list_file_form() -> None:
    # _load_as_allowlist expects servers to be a JSON LIST. `vault kv put key=value`
    # stores a STRING; the script writes the JSON via Vault's @file form instead.
    assert "@/tmp/as-allowlist.json" in _vault_text(), (
        "the AS allow-list must be written via the @/tmp/as-allowlist.json @file form"
    )


def test_vault_seed_allowlist_entry_carries_the_anyhttpurl_trailing_slash() -> None:
    # FastMCP wraps the AS issuer in pydantic AnyHttpUrl, which normalises
    # "http://h:9000" -> "http://h:9000/", so its PRM advertises the issuer WITH a trailing
    # slash. The kernel compares the PRM-advertised issuer against this allow-list by EXACT
    # string (RFC 8414 issuer semantics, mcp_authz.py:753 `s in allowed_servers`), so the
    # seeded entry MUST carry the same trailing slash or the carve-out refuses
    # mcp_as_not_allowlisted (Proof 1b-2 attempt-4 finding). Pin the slash-suffixed entry.
    assert "${AS}/" in _vault_text(), (
        "the AS allow-list must seed the issuer WITH the AnyHttpUrl trailing slash "
        "(servers entry must be ${AS}/, not the bare ${AS}) — the no-slash form silently "
        "fails the kernel's exact-string AS allow-list match"
    )


def test_vault_seed_never_uses_the_inline_servers_string_form() -> None:
    # The anti-pattern: `vault kv put ... servers=...` stores servers as a STRING,
    # not a JSON list, which _load_as_allowlist rejects. The @file form above is the
    # only legitimate path — assert the inline `servers=` form is absent entirely.
    assert "servers=" not in _vault_text(), (
        "seed-vault.sh must NOT use the inline `servers=` key=value form (it stores a "
        "string, not a JSON list) — the @/tmp/as-allowlist.json @file form is required"
    )


def test_vault_seed_reads_back_and_asserts_the_list_shape() -> None:
    # The readback assertion proves, at run time, that servers came back as a JSON
    # ARRAY under KV v1 (data.servers) — fail-loud if the @file put regressed.
    text = _vault_text()
    assert "kv get -format=json" in text, "must read the AS allow-list back as JSON"
    assert "isinstance(s,list)" in text, "must assert servers is a JSON list on readback"


# --- Vault root-token alignment guard (the attempt-2 BAR 0 defect) ----------------
#
# The proof reuses the chart's SHARED backends.yaml Vault, which boots with a fixed
# VAULT_DEV_ROOT_TOKEN_ID. seed-vault.sh (WRITES Vault) + proof-1b-2-values.yaml (the
# kernel's READ token) MUST both use THAT root token — else every `vault` call 403s.
# Attempt 2 died here: the proof used proof1b2-root-token but the backend boots
# smoke-root-token. Pin all three equal so a future drift is caught at author time,
# not at the live run (and so we never mutate the shared backends.yaml to compensate).

_BACKENDS_YAML = _REPO_ROOT / "infra" / "charts" / "agentos" / "ci" / "smoke" / "backends.yaml"
_VALUES_YAML = _SEED_DIR / "proof-1b-2-values.yaml"


def _backend_vault_root_token() -> str:
    m = re.search(r"VAULT_DEV_ROOT_TOKEN_ID,\s*value:\s*([^\s}]+)", _BACKENDS_YAML.read_text())
    assert m, "backends.yaml must set VAULT_DEV_ROOT_TOKEN_ID on the vault deployment"
    return m.group(1).strip().strip('"')


def test_vault_token_matches_the_reused_backend_root_token() -> None:
    backend = _backend_vault_root_token()
    seed_m = re.search(r"VAULT_TOKEN=(\S+)", _vault_text())
    assert seed_m, "seed-vault.sh must set VAULT_TOKEN"
    seed_token = seed_m.group(1)
    values_m = re.search(r'vaultToken:\s*"?([^"\s]+)"?', _VALUES_YAML.read_text())
    assert values_m, "proof-1b-2-values.yaml must set vaultToken"
    values_token = values_m.group(1)
    assert seed_token == backend, (
        f"seed-vault.sh VAULT_TOKEN ({seed_token!r}) must equal the reused backends.yaml "
        f"Vault VAULT_DEV_ROOT_TOKEN_ID ({backend!r}) — else `vault` 403s on every call "
        f"(the attempt-2 BAR 0 defect)"
    )
    assert values_token == backend, (
        f"proof-1b-2-values.yaml vaultToken ({values_token!r}) must equal the reused "
        f"backends.yaml Vault VAULT_DEV_ROOT_TOKEN_ID ({backend!r}) — else the kernel can't "
        f"read Vault"
    )
