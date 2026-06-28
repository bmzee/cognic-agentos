# M3-E2c — Deployed Oracle-Schema Governed-Proof Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy the *released, signed* `cognic-tool-oracle-schema@v0.1.0` into a kind-deployed AgentOS and prove the full governed MCP loop — boot-time trust registration → `discovery_status=auth_ready` → real `call_tool(describe_table)` — against an in-cluster seeded Oracle XE, with a **real RS256/JWKS** Authorization Server. A green run flips the M3 checkbox in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md`.

**Architecture:** Clone the proven Proof 1b-2 kind harness into a parallel `infra/proof-1b-2c/` tree, changing only the deltas: (1) the MCP tool Service becomes the released oracle pack image (built from the **downloaded GitHub Release wheel**, not a local rebuild); (2) an in-cluster `gvenzl/oracle-xe:21-slim` (`XEPDB1`) seeded with the `COGNIC.DEPARTMENTS`/`EMPLOYEES` fixture; (3) the emulated AS gains an **env-flagged RS256 mode** that mints signed JWTs (`iss`/`aud`/`exp`/`iat`/`nbf`/`scope`) + serves JWKS — required because the oracle pack does real JWT verification (the Proof 1b-2 example accepted any bearer); (4) the boot-trust staging tree carries the released signed bundle. The BAR 1 (allow-list permit + removed-delta) → BAR 2 (auth_ready + call_tool) proof structure is preserved verbatim; the must-have negative stays the allow-list-removed delta, with an optional, env-gated verifier-audience negative.

**Tech Stack:** kind, Helm (`infra/charts/agentos`), Docker, in-cluster Postgres + Vault (`infra/charts/agentos/ci/smoke/backends.yaml`), `gvenzl/oracle-xe:21-slim`, FastMCP (`mcp==1.27.0`) + uvicorn, `oracledb`, `PyJWT[crypto]` (pack verifier + the RS256 AS + its unit test), cosign-signed release attestations, `gh` CLI (release download).

## Global Constraints

- **Released artifact only (acceptance criterion #1).** The oracle pack wheel + its 7-attestation bundle + `cosign.pub` MUST come from the **GitHub Release `v0.1.0`** (`gh release download v0.1.0 --repo bmzee/cognic-tool-oracle-schema`), never a local rebuild. The released wheel sha256 MUST equal `4ed1a44773696429acf6bd5e88d91fa966ab9c4a0a3dc80925bac179883b1beb`; `cosign.pub` sha256 MUST equal `43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78`. Staging fail-closes on any mismatch.
- **Real RS256/JWKS, never `dev_insecure`.** The pack runs `COGNIC_AUTH_MODE=jwt` in the proof. `dev_insecure` is forbidden in the deployed proof (it would prove the wrong thing). The RS256 AS mode is **env-flagged** (`COGNIC_PROOF_AS_SIGNING_MODE`, default `unsigned`) so the Proof 1b-2 unsigned path stays **behaviorally unchanged** (its default `alg:none` token is pinned by the Task 1 regression test — the file is rewritten, so this is behavioral, not byte-level).
- **PyJWT is a new declared dev dependency.** AgentOS does not declare `PyJWT` directly today (`cryptography` + `joserfc` are declared under the `[adapters]` extra, but neither is used by this fixture). Task 1 adds `PyJWT[crypto]>=2.10,<3` to `[project.optional-dependencies].dev` (it backs the RS256 AS fixture + its unit test; the AS image installs the same lib; PyJWT is chosen explicitly to match the released oracle pack's own verifier — `PyJWKClient`). The `import jwt` in `_local_as.py` is lazy (inside the rs256 branch only) so the unsigned default never imports it.
- **Single-effective-URL invariant.** `http://10.96.0.51:8765/mcp` MUST be byte-identical across: the override-row `server_url_override`, the pack's `COGNIC_MCP_SERVER_URL` (PRM `resource_server_url`), the pack's `COGNIC_OAUTH_AUDIENCE`, the RFC-8707 `resource` AgentOS sends, and the AS-minted token `aud`. `http://192.88.99.9:9000` MUST be identical across the AS issuer, the pack's `COGNIC_MCP_AS_ISSUER`/`COGNIC_OAUTH_ISSUER`, and the token `iss`; the Vault AS allow-list entry carries it **with a trailing slash** (`http://192.88.99.9:9000/`) per the FastMCP `AnyHttpUrl` normalization + exact-string compare at `mcp_authz.py:753`.
- **Tenant** = `proof-1b-2c`. **Pack id** = `cognic-tool-oracle-schema`. **OAuth scope** = `oracle_schema.read` (manifest-driven; the AS echoes it; the pack requires it via `COGNIC_REQUIRED_SCOPES`). Portal-RBAC scopes on the proof actor stay `{mcp.tool.list, mcp.tool.invoke}`.
- **Do not modify the merged `infra/proof-1b-2/` tree, `tests/integration/proof_1b_2/`, or `tests/unit/proof_1b_2/`.** The only shared file edited is `tests/integration/pack_loop/_local_as.py` (additive, env-flagged; the default unsigned behavior is unchanged and pinned by the Task 1 regression test).
- **Operator-gated + env-gated.** The live runner is `COGNIC_RUN_PROOF_1B2C=1`-gated and exits 0 (skip) when unset. NO default-on CI job. Per-action authorization for every remote/kind action.
- **Branch handling (corrected — we are on `docs/m3-e2b-plan` @ `dacc989`, where the M3-E2b plan doc is tracked and only this M3-E2c plan is untracked):** commit **both plan docs to `docs/m3-e2b-plan`** (this is what "land both together" means — do *not* start from main for the docs). The **implementation** uses a fresh `feat/proof-1b-2c` branch off `main` (Task 1 step 1). In subagent-driven execution the controller passes each task's full text to the subagent (subagents do NOT read the plan file), so the plan doc's branch location does not gate execution. Land `docs/m3-e2b-plan` and `feat/proof-1b-2c` to main separately when each is green.

---

## File Structure

**New tree `infra/proof-1b-2c/` (mirrors `infra/proof-1b-2/`; YAML/Docker/scripts only — no Python packages here):**
- `Dockerfile.oracle-pack` — the MCP tool Service image; installs the pack's full runtime deps + the staged released wheel.
- `Dockerfile.agentos-proof` — proof AgentOS image; bakes the released-pack staging (`proof1b2c-staging/`) + the `proof_1b_2c` app. Near-identical to `infra/proof-1b-2/Dockerfile.agentos-proof`.
- `Dockerfile.as` — the AS image; mirror of `infra/proof-1b-2/Dockerfile.as` + `PyJWT[crypto]`.
- `manifests/oracle-pack.yaml` — Deployment+Service, static `clusterIP: 10.96.0.51`, the full pack env, an XE-wait initContainer.
- `manifests/oracle-xe.yaml` — `gvenzl/oracle-xe:21-slim` Deployment+Service (`oracle-xe:1521`, `XEPDB1`); mounts the **runner-created** `oracle-xe-seed` ConfigMap; readiness probe.
- `manifests/auth-server.yaml` — AS Deployment+Service at `externalIPs: ["192.88.99.9"]`, `COGNIC_PROOF_AS_SIGNING_MODE=rs256`. Mirror + env.
- `oracle-seed/seed_schema.sql` — **the single source of truth** for the fixture, copied verbatim from the released pack's `tests/fixtures/seed_schema.sql`. (The ConfigMap is generated from this file by the runner — no embedded copy, so no drift.)
- `seed-db.sh` — override row + allow-list row. Mirror + values.
- `seed-vault.sh` — OAuth creds + AS allow-list for tenant `proof-1b-2c`. Mirror + values.
- `proof-1b-2c-values.yaml` — Helm overlay. Mirror of `proof-1b-2-values.yaml`, `image.tag: proof1b2c`.
- `migrate-job.yaml` — non-hook migration Job (`__AGENTOS_IMAGE__` slot). Verbatim mirror.
- `run-proof-1b-2c.sh` — the operator runner.
- `README.md` — proof-only-binder caveat + run instructions.

**New `tests/integration/proof_1b_2c/` (importable underscored package — mirrors `tests/integration/proof_1b/` + `proof_1b_2/`):**
- `__init__.py`
- `proof_app.py` — the fixed-actor `create_proof_app` (tenant `proof-1b-2c`). Mirror of `tests/integration/proof_1b_2/proof_app.py`.
- `stage_released_pack.py` — downloads the v0.1.0 Release assets, verifies digests, arranges the trust-staging tree. **Lives here (not under the hyphenated infra dir) so it is importable as `tests.integration.proof_1b_2c.stage_released_pack` and runnable via `python -m …`, exactly like `tests/integration/proof_1b/stage_trust_inputs.py`.**

**New `tests/unit/proof_1b_2c/`:** `__init__.py` + structural pins — `test_as_rs256.py`, `test_stage_released_pack.py`, `test_oracle_pack_image.py`, `test_oracle_xe_manifest.py`, `test_oracle_pack_manifest.py`, `test_as_manifest.py`, `test_proof_app.py`, `test_seeds.py`, `test_values.py`, `test_runner.py`.

**Edited (shared, additive):** `tests/integration/pack_loop/_local_as.py` (env-flagged RS256 mode + JWKS); `pyproject.toml` (`[dev]` += `PyJWT[crypto]`); `.gitignore` (the transient `infra/proof-1b-2c/proof1b2c-staging/` + `infra/proof-1b-2c/proof_1b_2c/` build-context copies).

**Edited at close-out:** `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` (M3 checkbox), `docs/VALIDATION-RESULTS.md` (the proof record).

---

## Task 1: Env-flagged RS256 mode for the AS fixture (+ the PyJWT dev dep)

**Files:**
- Modify: `pyproject.toml`, `uv.lock` (include if `uv sync --extra dev` changes it — `uv.lock` is tracked), `tests/integration/pack_loop/_local_as.py`
- Create: `tests/unit/proof_1b_2c/__init__.py`, `tests/unit/proof_1b_2c/test_as_rs256.py`

**Interfaces:**
- Produces: an AS that, when `COGNIC_PROOF_AS_SIGNING_MODE=rs256`, serves `GET /.well-known/oauth-authorization-server → {token_endpoint, issuer, jwks_uri}`, `GET /.well-known/jwks.json → {keys:[RSA JWK]}`, and `POST /token → {access_token}` where `access_token` is an RS256 JWT with `{iss, aud=<resource>, exp, iat, nbf, scope}`. Default (unset / `unsigned`) keeps the exact current `alg:none` behavior.

- [ ] **Step 1: Branch off main for the implementation**

```bash
cd /Users/bmz/development/cognic-agentos
git checkout main && git pull --ff-only
git checkout -b feat/proof-1b-2c
```

- [ ] **Step 2: Add the PyJWT dev dep** — in `pyproject.toml`, append to `[project.optional-dependencies].dev` (after `respx>=0.22`):

```toml
    # M3-E2c — the deployed-proof RS256 AS fixture (tests/integration/pack_loop/
    # _local_as.py, rs256 mode) signs JWTs + serves JWKS, and its unit test
    # verifies them. PyJWT[crypto] is the lib the released oracle pack's own
    # verifier uses; declaring it here (PyJWT is undeclared today; cryptography
    # + joserfc live under the [adapters] extra) makes the test's `import jwt`
    # explicit, not a transitive accident. The AS *image* installs the same lib.
    "PyJWT[crypto]>=2.10,<3",
```

Then: `uv sync --extra dev`.

- [ ] **Step 3: Write the failing test** — `tests/unit/proof_1b_2c/__init__.py` (empty) + `tests/unit/proof_1b_2c/test_as_rs256.py`:

```python
"""RS256 mode for the proof AS fixture (M3-E2c Task 1). The unsigned path
(Proof 1b-2) MUST stay behaviorally unchanged (same alg:none token); the rs256
path mints a verifiable RS256 JWT and serves a JWKS the pack's PyJWKClient can
consume."""
from __future__ import annotations

import base64
import importlib
import json

import jwt
from starlette.testclient import TestClient


def _reload(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return importlib.reload(importlib.import_module("tests.integration.pack_loop._local_as"))


def test_unsigned_mode_is_unchanged(monkeypatch):
    monkeypatch.delenv("COGNIC_PROOF_AS_SIGNING_MODE", raising=False)
    mod = _reload(monkeypatch, COGNIC_PROOF_AS_ISSUER="http://as.test:9000")
    client = TestClient(mod.build_app())
    tok = client.post(
        "/token", data={"scope": "oracle_schema.read", "resource": "http://rs.test/mcp"}
    ).json()["access_token"]
    assert tok.endswith(".sig")  # decorative signature unchanged
    hdr = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
    assert hdr["alg"] == "none"


def test_rs256_mode_mints_verifiable_jwt_and_serves_jwks(monkeypatch):
    mod = _reload(
        monkeypatch,
        COGNIC_PROOF_AS_SIGNING_MODE="rs256",
        COGNIC_PROOF_AS_ISSUER="http://as.test:9000",
    )
    client = TestClient(mod.build_app())

    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == "http://as.test:9000"
    assert meta["jwks_uri"] == "http://as.test:9000/.well-known/jwks.json"

    jwks = client.get("/.well-known/jwks.json").json()
    key = jwks["keys"][0]
    assert key["kty"] == "RSA" and key["use"] == "sig" and key["alg"] == "RS256"

    resource = "http://10.96.0.51:8765/mcp"
    tok = client.post(
        "/token", data={"scope": "oracle_schema.read", "resource": resource}
    ).json()["access_token"]
    assert jwt.get_unverified_header(tok)["kid"] == key["kid"]
    claims = jwt.decode(
        tok, jwt.PyJWK(key).key, algorithms=["RS256"], audience=resource,
        issuer="http://as.test:9000", options={"require": ["exp", "iat", "nbf"]},
    )
    assert claims["scope"] == "oracle_schema.read"
    assert claims["aud"] == resource and claims["iss"] == "http://as.test:9000"
```

- [ ] **Step 4: Run it, watch it fail** — `uv run pytest tests/unit/proof_1b_2c/test_as_rs256.py -q` → FAIL (`jwks_uri` KeyError / no jwks route / `alg` none in rs256).

- [ ] **Step 5: Implement** `tests/integration/pack_loop/_local_as.py` — full body (the unsigned default behavior is unchanged; adds the env-gated rs256 branch):

```python
# tests/integration/pack_loop/_local_as.py
"""A tiny localhost OAuth2 client-credentials authorization server.

Two modes (env COGNIC_PROOF_AS_SIGNING_MODE):
  * "unsigned" (default) — Proof 1a/1b-2 path. The access token is an alg:none
    JWT carrying only {aud=<resource>, scope}; the signature is decorative
    (AgentOS validates `aud`, trusts the AS via the per-tenant allow-list).
  * "rs256" — M3-E2c path. Mints an RS256-signed JWT
    {iss, aud=<resource>, exp, iat, nbf, scope} and serves a JWKS endpoint so a
    real resource-server verifier (the oracle pack's PyJWKClient) can verify it.
"""

from __future__ import annotations

import base64
import json
import os
import time

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

_AS_ISSUER = os.environ.get("COGNIC_PROOF_AS_ISSUER", "http://127.0.0.1:9000")
_SIGNING_MODE = os.environ.get("COGNIC_PROOF_AS_SIGNING_MODE", "unsigned")
_KID = "proof-1b-2c-rs256"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _rsa_material() -> tuple[object, dict]:
    # rs256 only. Process-lifetime keypair (the AS pod is single-replica + stable
    # for a run; a restart rotates the key, which is fine — the pack fetches JWKS
    # fresh and AgentOS re-acquires the token on a cold boot).
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk.update({"use": "sig", "alg": "RS256", "kid": _KID})
    return priv, jwk


_RSA_PRIV: object | None = None
_RSA_JWK: dict | None = None
if _SIGNING_MODE == "rs256":
    _RSA_PRIV, _RSA_JWK = _rsa_material()


async def _metadata(_request: Request) -> JSONResponse:
    body = {"token_endpoint": f"{_AS_ISSUER}/token", "issuer": _AS_ISSUER}
    if _SIGNING_MODE == "rs256":
        body["jwks_uri"] = f"{_AS_ISSUER}/.well-known/jwks.json"
    return JSONResponse(body)


async def _jwks(_request: Request) -> JSONResponse:
    assert _RSA_JWK is not None, "jwks route is registered only in rs256 mode"
    return JSONResponse({"keys": [_RSA_JWK]})


async def _token(request: Request) -> JSONResponse:
    form = await request.form()
    requested_scope = str(form.get("scope", "mcp:tools"))
    resource = str(form.get("resource", ""))  # RFC 8707 resource indicator == server_url
    if _SIGNING_MODE == "rs256":
        import jwt

        now = int(time.time())
        access_token = jwt.encode(
            {"iss": _AS_ISSUER, "aud": resource, "scope": requested_scope,
             "iat": now, "nbf": now, "exp": now + 3600},
            _RSA_PRIV, algorithm="RS256", headers={"kid": _KID},
        )
    else:
        header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8"))
        payload = _b64url(json.dumps({"aud": resource, "scope": requested_scope}).encode("utf-8"))
        access_token = f"{header}.{payload}.sig"
    return JSONResponse(
        {"access_token": access_token, "token_type": "Bearer",
         "expires_in": 3600, "scope": requested_scope}
    )


def build_app() -> Starlette:
    routes = [
        Route("/.well-known/oauth-authorization-server", _metadata, methods=["GET"]),
        Route("/token", _token, methods=["POST"]),
    ]
    if _SIGNING_MODE == "rs256":
        routes.append(Route("/.well-known/jwks.json", _jwks, methods=["GET"]))
    return Starlette(routes=routes)


def run_local_as(*, port: int = 9000) -> None:
    uvicorn.run(
        build_app(), host=os.environ.get("COGNIC_PROOF_AS_HOST", "127.0.0.1"),
        port=port, log_level="warning",
    )


if __name__ == "__main__":
    run_local_as(port=int(os.environ.get("COGNIC_PROOF_AS_PORT", "9000")))
```

- [ ] **Step 6: Run the test, watch it pass** — `uv run pytest tests/unit/proof_1b_2c/test_as_rs256.py -q`.

- [ ] **Step 7: Confirm the Proof 1b-2 unsigned path is behaviorally unchanged** — `uv run pytest tests/unit/proof_1b_2/ tests/integration/pack_loop/ -q` (no regression; default mode never imports `jwt`).

- [ ] **Step 8: Full gate + commit**

```bash
uv run ruff check tests && uv run ruff format --check tests && uv run mypy tests/integration/pack_loop/_local_as.py
# include uv.lock too if `uv sync --extra dev` changed it (uv.lock is tracked; no-op if unchanged)
git add pyproject.toml uv.lock tests/integration/pack_loop/_local_as.py \
        tests/unit/proof_1b_2c/__init__.py tests/unit/proof_1b_2c/test_as_rs256.py
git commit -m "feat(proof-1b-2c): env-flagged RS256+JWKS AS mode (+PyJWT dev dep)"
```

---

## Task 2: Released-pack staging helper (importable package)

**Files:**
- Create: `tests/integration/proof_1b_2c/__init__.py`, `tests/integration/proof_1b_2c/stage_released_pack.py`
- Test: `tests/unit/proof_1b_2c/test_stage_released_pack.py`

**Interfaces:**
- `python -m tests.integration.proof_1b_2c.stage_released_pack <out_dir>` produces the staging tree the proof AgentOS image consumes — **matching `stage_trust_inputs.py` + `Dockerfile.agentos-proof` exactly**: `<out>/wheel/<wheel>`, `<out>/pack-attestations/cognic-tool-oracle-schema/0.1.0/{<wheel>, 7 attestations}`, `<out>/trust-roots/_default/cosign.pub`, `<out>/policies/plugin_allowlist.json`, `<out>/alembic.ini`. (The image's `COPY proof1b2c-staging/policies/` + `COPY proof1b2c-staging/alembic.ini` lines require these exact paths — root-level `plugin_allowlist.json` or a missing `alembic.ini` breaks the build/migrate path.)

- [ ] **Step 1: Write the failing test** (imports the package normally — no `sys.path`/`spec_from_file_location` hack needed, the module is a real package):

```python
"""stage_released_pack arranges downloaded v0.1.0 assets into the staging tree
the proof image consumes + fail-closes on a digest mismatch (M3-E2c Task 2)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.integration.proof_1b_2c import stage_released_pack as srp


def _fake_assets(d: Path, wheel_bytes: bytes, pub_bytes: bytes) -> Path:
    src = d / "downloaded"
    src.mkdir()
    (src / srp.WHEEL).write_bytes(wheel_bytes)
    (src / "cosign.pub").write_bytes(pub_bytes)
    for name in srp.ATTESTATIONS:
        (src / name).write_text("{}")
    return src


def test_arrange_builds_the_exact_image_tree(tmp_path, monkeypatch):
    wheel, pub = b"WHEEL", b"PUB"
    monkeypatch.setattr(srp, "EXPECTED_WHEEL_SHA256", hashlib.sha256(wheel).hexdigest())
    monkeypatch.setattr(srp, "EXPECTED_PUB_SHA256", hashlib.sha256(pub).hexdigest())
    src = _fake_assets(tmp_path, wheel, pub)
    dst = tmp_path / "staging"
    srp.arrange(src, dst)
    assert (dst / "wheel" / srp.WHEEL).read_bytes() == wheel
    base = dst / "pack-attestations" / "cognic-tool-oracle-schema" / "0.1.0"
    assert (base / srp.WHEEL).exists() and (base / "cosign.sig").exists()
    assert (dst / "trust-roots" / "_default" / "cosign.pub").read_bytes() == pub
    # P1 layout fix: allow-list under policies/, and alembic.ini present.
    assert json.loads((dst / "policies" / "plugin_allowlist.json").read_text()) == {
        "_default": ["cognic-tool-oracle-schema"]
    }
    assert (dst / "alembic.ini").exists() and (dst / "alembic.ini").read_bytes()


def test_digest_mismatch_fails_closed(tmp_path, monkeypatch):
    src = _fake_assets(tmp_path, b"WHEEL", b"PUB")
    monkeypatch.setattr(srp, "EXPECTED_WHEEL_SHA256", "deadbeef")
    with pytest.raises(srp.StagingDigestMismatch):
        srp.arrange(src, tmp_path / "staging")
```

- [ ] **Step 2: Run, watch fail** (`ModuleNotFoundError`).

- [ ] **Step 3: Implement** `tests/integration/proof_1b_2c/__init__.py` (empty) + `tests/integration/proof_1b_2c/stage_released_pack.py`:

```python
"""Download + stage the RELEASED, signed cognic-tool-oracle-schema@v0.1.0 for the
M3-E2c boot-trust gate. Released artifact only (acceptance criterion #1) — never a
local rebuild. Produces the same staging-tree shape stage_trust_inputs.py emits
(so Dockerfile.agentos-proof consumes it identically), but by DOWNLOAD not build.
From repo root: python -m tests.integration.proof_1b_2c.stage_released_pack <out>."""
from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# tests/integration/proof_1b_2c/stage_released_pack.py -> parents[3] == repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]

PACK_ID = "cognic-tool-oracle-schema"
VERSION = "0.1.0"
WHEEL = f"cognic_tool_oracle_schema-{VERSION}-py3-none-any.whl"
RELEASE_TAG = "v0.1.0"
RELEASE_REPO = "bmzee/cognic-tool-oracle-schema"
ATTESTATIONS = (
    "cosign.sig", "bundle.sigstore", "sbom.cdx.json", "slsa-provenance.intoto.json",
    "intoto-layout.json", "vuln-scan.json", "license-audit.json",
)
EXPECTED_WHEEL_SHA256 = "4ed1a44773696429acf6bd5e88d91fa966ab9c4a0a3dc80925bac179883b1beb"
EXPECTED_PUB_SHA256 = "43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78"
_ALLOWLIST = {"_default": [PACK_ID]}


class StagingDigestMismatch(RuntimeError):
    pass


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def download(dst_dir: Path) -> Path:
    dst_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["gh", "release", "download", RELEASE_TAG, "--repo", RELEASE_REPO,
         "--dir", str(dst_dir), "--clobber"],
        check=True,
    )
    return dst_dir


def arrange(src: Path, dst: Path) -> None:
    wheel, pub = src / WHEEL, src / "cosign.pub"
    got_wheel, got_pub = _sha256(wheel), _sha256(pub)
    if got_wheel != EXPECTED_WHEEL_SHA256:
        raise StagingDigestMismatch(f"wheel sha256 {got_wheel} != {EXPECTED_WHEEL_SHA256}")
    if got_pub != EXPECTED_PUB_SHA256:
        raise StagingDigestMismatch(f"cosign.pub sha256 {got_pub} != {EXPECTED_PUB_SHA256}")
    if dst.exists():
        shutil.rmtree(dst)
    (dst / "wheel").mkdir(parents=True)
    shutil.copy2(wheel, dst / "wheel" / WHEEL)
    att = dst / "pack-attestations" / PACK_ID / VERSION
    att.mkdir(parents=True)
    shutil.copy2(wheel, att / WHEEL)
    for name in ATTESTATIONS:
        shutil.copy2(src / name, att / name)
    troot = dst / "trust-roots" / "_default"
    troot.mkdir(parents=True)
    shutil.copy2(pub, troot / "cosign.pub")
    # P1 layout: allow-list under policies/ (Dockerfile copies proof1b2c-staging/policies/);
    # alembic.ini from the repo (Gap-5 — the image carries the migration pkg but not the ini).
    policies = dst / "policies"
    policies.mkdir(parents=True)
    (policies / "plugin_allowlist.json").write_text(json.dumps(_ALLOWLIST), encoding="utf-8")
    shutil.copy2(_REPO_ROOT / "alembic.ini", dst / "alembic.ini")
    # group/other read (+x on dirs) so the non-root `cognic` image user can read it
    for p in dst.rglob("*"):
        p.chmod(
            p.stat().st_mode | stat.S_IRGRP | stat.S_IROTH
            | ((stat.S_IXGRP | stat.S_IXOTH) if p.is_dir() else 0)
        )


def main(dst: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        arrange(download(Path(tmp)), Path(dst))
    print(f"staged released {PACK_ID}@{VERSION} -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1])
```

- [ ] **Step 4: Run, watch pass** — `uv run pytest tests/unit/proof_1b_2c/test_stage_released_pack.py -q`.

- [ ] **Step 5: OPEN VERIFICATION (do early; do NOT weaken the gate).** Read `src/cognic_agentos/protocol/pack_attestation_resolver.py` (`resolve_pack_attestations`) + compare the produced `pack-attestations/cognic-tool-oracle-schema/0.1.0/` set to the working Proof 1b-2 `infra/proof-1b/proof1b-staging/pack-attestations/cognic-tool-search/0.1.0/` set. Confirm the **released** in-toto layout + the attestation filename set satisfy the boot trust gate's Wave-1/ADR-016 contract for a *downloaded* (not locally-built) pack. If the resolver expects a different filename/layout, align `ATTESTATIONS`/`arrange()`; if the released bundle is structurally incompatible with the boot gate, **stop and raise it as a design finding** (the gate is not negotiable). This is the plan's highest-risk unknown.

- [ ] **Step 6: Commit**

```bash
git add tests/integration/proof_1b_2c/__init__.py \
        tests/integration/proof_1b_2c/stage_released_pack.py \
        tests/unit/proof_1b_2c/test_stage_released_pack.py
git commit -m "feat(proof-1b-2c): download+stage the released v0.1.0 signed pack"
```

---

## Task 3: The oracle-pack tool-Service image

**Files:** Create `infra/proof-1b-2c/Dockerfile.oracle-pack`; Test `tests/unit/proof_1b_2c/test_oracle_pack_image.py`.

- [ ] **Step 1: Failing test**:

```python
from pathlib import Path
DF = Path("infra/proof-1b-2c/Dockerfile.oracle-pack").read_text()


def test_installs_full_runtime_deps():
    for dep in ("mcp==1.27.0", "uvicorn[standard]", "oracledb", "PyJWT[crypto]"):
        assert dep in DF


def test_installs_staged_released_wheel_and_runs_server():
    assert "proof1b2c-staging/wheel/cognic_tool_oracle_schema-0.1.0-py3-none-any.whl" in DF
    assert 'CMD ["python", "-m", "cognic_tool_oracle_schema.server"]' in DF
```

- [ ] **Step 2: Run, watch fail. Step 3: Implement** `infra/proof-1b-2c/Dockerfile.oracle-pack` (build context = `infra/proof-1b-2c/`; reads the staged wheel from `proof1b2c-staging/` produced by Task 2):

```dockerfile
# infra/proof-1b-2c/Dockerfile.oracle-pack — the released oracle-schema MCP tool
# Service. Built from the DOWNLOADED v0.1.0 release wheel (criterion #1) staged at
# proof1b2c-staging/wheel/, with the pack's full runtime deps. Context = infra/proof-1b-2c/.
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir \
      "mcp==1.27.0" "uvicorn[standard]>=0.35" "oracledb>=2.5" "PyJWT[crypto]>=2.10,<3"
COPY proof1b2c-staging/wheel/cognic_tool_oracle_schema-0.1.0-py3-none-any.whl /tmp/
RUN pip install --no-cache-dir --no-deps /tmp/cognic_tool_oracle_schema-0.1.0-py3-none-any.whl
CMD ["python", "-m", "cognic_tool_oracle_schema.server"]
```

- [ ] **Step 4: Run, watch pass. Step 5: Commit** (`feat(proof-1b-2c): oracle-pack tool-Service image from the released wheel`).

---

## Task 4: In-cluster Oracle XE + seed (no embedded copy)

**Files:** Create `infra/proof-1b-2c/manifests/oracle-xe.yaml`, `infra/proof-1b-2c/oracle-seed/seed_schema.sql`; Test `tests/unit/proof_1b_2c/test_oracle_xe_manifest.py`.

> **P2 drift fix:** the seed lives ONLY in `oracle-seed/seed_schema.sql`. The runner creates the `oracle-xe-seed` ConfigMap from that file via `kubectl create configmap --from-file` (Task 10); the manifest does NOT embed a second copy — so drift is structurally impossible (single source of truth), which is stronger than guarding a duplicated copy.

- [ ] **Step 1: Copy the fixture** — `infra/proof-1b-2c/oracle-seed/seed_schema.sql` is a **verbatim copy** of `/Users/bmz/development/cognic-tool-oracle-schema/tests/fixtures/seed_schema.sql` (`ALTER SESSION SET CONTAINER = XEPDB1`; `CREATE TABLE cognic.departments` PK + `cognic.employees` PK/UNIQUE/CHECK/FK + comments + 4 demo rows; `WHENEVER SQLERROR EXIT`).

- [ ] **Step 2: Failing test**:

```python
from pathlib import Path
import yaml

DOCS = list(yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/oracle-xe.yaml").read_text()))
SEED = Path("infra/proof-1b-2c/oracle-seed/seed_schema.sql").read_text()
DEP = next(d for d in DOCS if d["kind"] == "Deployment")
C = DEP["spec"]["template"]["spec"]["containers"][0]


def test_xe_image_env_and_service():
    assert C["image"] == "gvenzl/oracle-xe:21-slim"
    env = {e["name"]: e.get("value") for e in C["env"]}
    assert env["APP_USER"] == "cognic" and env["ORACLE_DATABASE"] == "XEPDB1"
    svc = next(d for d in DOCS if d["kind"] == "Service")
    assert svc["metadata"]["name"] == "oracle-xe" and svc["spec"]["ports"][0]["port"] == 1521


def test_no_embedded_configmap_single_source_seed():
    # P2: the manifest must NOT carry a ConfigMap copy of the seed (drift root-cause).
    assert not any(d.get("kind") == "ConfigMap" for d in DOCS)
    vol = next(v for v in DEP["spec"]["template"]["spec"]["volumes"] if v["name"] == "seed")
    assert vol["configMap"]["name"] == "oracle-xe-seed"  # runner-created from the file
    assert "/container-entrypoint-initdb.d" in {m["mountPath"] for m in C["volumeMounts"]}


def test_seed_file_creates_cognic_objects():
    assert "ALTER SESSION SET CONTAINER = XEPDB1" in SEED
    assert "cognic.departments" in SEED and "cognic.employees" in SEED


def test_readiness_probe_present():
    assert C["readinessProbe"]["exec"]["command"]  # gvenzl healthcheck.sh
```

- [ ] **Step 3: Run, watch fail. Step 4: Implement** `infra/proof-1b-2c/manifests/oracle-xe.yaml` (Deployment + Service only — the `oracle-xe-seed` ConfigMap is created by the runner from the seed file):

```yaml
# infra/proof-1b-2c/manifests/oracle-xe.yaml — in-cluster Oracle XE for M3-E2c.
# The oracle-xe-seed ConfigMap is created by run-proof-1b-2c.sh from
# oracle-seed/seed_schema.sql (single source of truth — no embedded copy).
# gvenzl runs every *.sql in /container-entrypoint-initdb.d once on first boot.
apiVersion: apps/v1
kind: Deployment
metadata: { name: oracle-xe, labels: { app: oracle-xe } }
spec:
  replicas: 1
  selector: { matchLabels: { app: oracle-xe } }
  template:
    metadata: { labels: { app: oracle-xe } }
    spec:
      containers:
      - name: oracle-xe
        image: gvenzl/oracle-xe:21-slim
        imagePullPolicy: IfNotPresent
        ports: [{ containerPort: 1521 }]
        env:
        - { name: ORACLE_PASSWORD, value: "proof_admin_only" }
        - { name: ORACLE_DATABASE, value: "XEPDB1" }
        - { name: APP_USER, value: "cognic" }
        - { name: APP_USER_PASSWORD, value: "cognic_dev_only" }
        volumeMounts:
        - { name: seed, mountPath: /container-entrypoint-initdb.d }
        readinessProbe:
          exec: { command: ["/bin/sh", "-c", "healthcheck.sh"] }
          initialDelaySeconds: 60
          periodSeconds: 15
          timeoutSeconds: 10
          failureThreshold: 40   # XE first-boot ~3-5 min on an amd64 runner
      volumes:
      - name: seed
        configMap: { name: oracle-xe-seed }
---
apiVersion: v1
kind: Service
metadata: { name: oracle-xe }
spec:
  selector: { app: oracle-xe }
  ports: [{ port: 1521, targetPort: 1521 }]
```

- [ ] **Step 5: Run, watch pass. Step 6: Commit** (`feat(proof-1b-2c): in-cluster Oracle XE manifest + single-source seed`).

---

## Task 5: The oracle-pack manifest

**Files:** Create `infra/proof-1b-2c/manifests/oracle-pack.yaml`; Test `tests/unit/proof_1b_2c/test_oracle_pack_manifest.py`.

- [ ] **Step 1: Failing test** (pins the static ClusterIP, the single-effective-URL invariant, jwt-never-dev_insecure, the XE-wait initContainer):

```python
from pathlib import Path
import yaml

DOCS = list(yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/oracle-pack.yaml").read_text()))
DEP = next(d for d in DOCS if d["kind"] == "Deployment")
SVC = next(d for d in DOCS if d["kind"] == "Service")
ENV = {e["name"]: e.get("value") for e in DEP["spec"]["template"]["spec"]["containers"][0]["env"]}
SERVER_URL, AS_ISSUER = "http://10.96.0.51:8765/mcp", "http://192.88.99.9:9000"


def test_static_clusterip():
    assert SVC["spec"]["clusterIP"] == "10.96.0.51"


def test_single_effective_url_invariant():
    assert ENV["COGNIC_MCP_SERVER_URL"] == SERVER_URL == ENV["COGNIC_OAUTH_AUDIENCE"]


def test_issuer_invariant():
    assert ENV["COGNIC_MCP_AS_ISSUER"] == AS_ISSUER == ENV["COGNIC_OAUTH_ISSUER"]
    assert ENV["COGNIC_OAUTH_JWKS_URI"] == f"{AS_ISSUER}/.well-known/jwks.json"


def test_real_jwt_never_dev_insecure():
    assert ENV["COGNIC_AUTH_MODE"] == "jwt" and "COGNIC_ENV" not in ENV
    assert ENV["COGNIC_REQUIRED_SCOPES"] == "oracle_schema.read"


def test_oracle_connection_and_owner_allowlist():
    assert ENV["COGNIC_ORACLE_DSN"] == "oracle-xe:1521/XEPDB1"
    assert ENV["COGNIC_ORACLE_USER"] == "cognic"
    assert ENV["COGNIC_ORACLE_ALLOWED_OWNERS"] == "COGNIC"


def test_waits_for_xe():
    init = DEP["spec"]["template"]["spec"]["initContainers"][0]
    assert "oracle-xe 1521" in " ".join(init["command"])
```

- [ ] **Step 2: Run, watch fail. Step 3: Implement** `infra/proof-1b-2c/manifests/oracle-pack.yaml`:

```yaml
# infra/proof-1b-2c/manifests/oracle-pack.yaml — the released oracle-schema MCP
# tool Service. Static private ClusterIP 10.96.0.51 (override + allow-list seed
# this exact IP). jwt mode = the REAL RS256/JWKS verifier (never dev_insecure).
apiVersion: apps/v1
kind: Deployment
metadata: { name: proof-oracle-pack, labels: { app: proof-oracle-pack } }
spec:
  replicas: 1
  selector: { matchLabels: { app: proof-oracle-pack } }
  template:
    metadata: { labels: { app: proof-oracle-pack } }
    spec:
      initContainers:
      - name: wait-for-xe
        image: busybox:1.36
        command: ["sh", "-c", "until nc -z oracle-xe 1521; do echo waiting for oracle-xe; sleep 5; done"]
      containers:
      - name: oracle-pack
        image: cognic-proof-oracle-pack:1b2c
        imagePullPolicy: IfNotPresent
        ports: [{ containerPort: 8765 }]
        env:
        - { name: COGNIC_MCP_HOST, value: "0.0.0.0" }
        - { name: COGNIC_MCP_PORT, value: "8765" }
        - { name: COGNIC_MCP_SERVER_URL, value: "http://10.96.0.51:8765/mcp" }
        - { name: COGNIC_MCP_AS_ISSUER, value: "http://192.88.99.9:9000" }
        - { name: COGNIC_AUTH_MODE, value: "jwt" }
        - { name: COGNIC_OAUTH_ISSUER, value: "http://192.88.99.9:9000" }
        - { name: COGNIC_OAUTH_JWKS_URI, value: "http://192.88.99.9:9000/.well-known/jwks.json" }
        - { name: COGNIC_OAUTH_AUDIENCE, value: "http://10.96.0.51:8765/mcp" }
        - { name: COGNIC_REQUIRED_SCOPES, value: "oracle_schema.read" }
        - { name: COGNIC_ORACLE_DSN, value: "oracle-xe:1521/XEPDB1" }
        - { name: COGNIC_ORACLE_USER, value: "cognic" }
        - { name: COGNIC_ORACLE_PASSWORD, value: "cognic_dev_only" }
        - { name: COGNIC_ORACLE_ALLOWED_OWNERS, value: "COGNIC" }
---
apiVersion: v1
kind: Service
metadata: { name: proof-oracle-pack }
spec:
  clusterIP: 10.96.0.51
  selector: { app: proof-oracle-pack }
  ports: [{ port: 8765, targetPort: 8765 }]
```

- [ ] **Step 4: Run, watch pass. Step 5: Commit** (`feat(proof-1b-2c): oracle-pack Deployment+Service manifest`).

---

## Task 6: The RS256 AS image + manifest

**Files:** Create `infra/proof-1b-2c/Dockerfile.as`, `infra/proof-1b-2c/manifests/auth-server.yaml`; Test `tests/unit/proof_1b_2c/test_as_manifest.py`.

- [ ] **Step 1: Failing test**:

```python
from pathlib import Path
import yaml

DF = Path("infra/proof-1b-2c/Dockerfile.as").read_text()
DOCS = list(yaml.safe_load_all(Path("infra/proof-1b-2c/manifests/auth-server.yaml").read_text()))


def test_as_image_installs_pyjwt_crypto():
    assert "PyJWT[crypto]" in DF and "_local_as.py" in DF


def test_as_manifest_rs256_mode_and_externalip():
    dep = next(d for d in DOCS if d["kind"] == "Deployment")
    env = {e["name"]: e.get("value") for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["COGNIC_PROOF_AS_SIGNING_MODE"] == "rs256"
    assert env["COGNIC_PROOF_AS_ISSUER"] == "http://192.88.99.9:9000"
    svc = next(d for d in DOCS if d["kind"] == "Service")
    assert svc["spec"]["externalIPs"] == ["192.88.99.9"]
```

- [ ] **Step 2: Run, watch fail. Step 3: Implement.** `Dockerfile.as` (context `infra/proof-1b-2c/`; the runner vendors `_local_as.py` in — Task 10):

```dockerfile
# infra/proof-1b-2c/Dockerfile.as — emulated AS, RS256 mode (M3-E2c).
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir "uvicorn[standard]" starlette python-multipart "PyJWT[crypto]>=2.10,<3"
COPY _local_as.py /app/_local_as.py
CMD ["python", "_local_as.py"]
```

`manifests/auth-server.yaml` mirrors `infra/proof-1b-2/manifests/auth-server.yaml` — image `cognic-proof-as:1b2c`, `externalIPs: ["192.88.99.9"]`, env `COGNIC_PROOF_AS_HOST=0.0.0.0`, `COGNIC_PROOF_AS_ISSUER=http://192.88.99.9:9000`, `COGNIC_PROOF_AS_PORT=9000`, **plus** `{name: COGNIC_PROOF_AS_SIGNING_MODE, value: "rs256"}`.

- [ ] **Step 4: Run, watch pass. Step 5: Commit** (`feat(proof-1b-2c): RS256 AS image + manifest`).

---

## Task 7: The proof AgentOS image + the proof_1b_2c app

**Files:** Create `infra/proof-1b-2c/Dockerfile.agentos-proof`, `tests/integration/proof_1b_2c/proof_app.py`; Test `tests/unit/proof_1b_2c/test_proof_app.py`. (`tests/integration/proof_1b_2c/__init__.py` already exists from Task 2.)

- [ ] **Step 1: `proof_app.py`** — copy `tests/integration/proof_1b_2/proof_app.py` verbatim, changing only `PROOF_TENANT = "proof-1b-2c"` and the CMD-referenced module path (the binder class `ProofActorBinder` with `def bind(self, *, request: Request | None) -> Actor`, `PROOF_SCOPES: Final[frozenset[MCPRBACScope]]`, and `create_proof_app()` calling `create_app(adapter_registry=bundled_registry)` then setting `app.state.actor_binder` are kept identical).

- [ ] **Step 2: Failing test** — uses the real binder signature `bind(request=None)`:

```python
from tests.integration.proof_1b_2c.proof_app import PROOF_TENANT, ProofActorBinder


def test_binds_proof_1b_2c_tenant():
    actor = ProofActorBinder().bind(request=None)
    assert PROOF_TENANT == "proof-1b-2c"
    assert actor.tenant_id == "proof-1b-2c"
    assert {"mcp.tool.list", "mcp.tool.invoke"} <= set(actor.scopes)
    assert actor.actor_type == "service"
```

- [ ] **Step 3: Run, watch fail. Step 4: Implement** `infra/proof-1b-2c/Dockerfile.agentos-proof` — mirror of `infra/proof-1b-2/Dockerfile.agentos-proof` with `proof1b-staging` → `proof1b2c-staging` and `proof_1b_2` → `proof_1b_2c`:

```dockerfile
ARG BASE_IMAGE=cognic-agentos:proof1b2-base
FROM ${BASE_IMAGE}
USER root
# trust staging (released pack): wheel install + attestations + trust roots + alembic.ini
COPY proof1b2c-staging/wheel/ /tmp/wheel/
RUN /opt/venv/bin/python -m ensurepip --upgrade \
 && /opt/venv/bin/python -m pip install --no-deps --no-cache-dir /tmp/wheel/*.whl && rm -rf /tmp/wheel
COPY proof1b2c-staging/pack-attestations/ /opt/cognic/pack-attestations/
COPY proof1b2c-staging/trust-roots/ /opt/cognic/trust-roots/
COPY proof1b2c-staging/policies/ /opt/cognic/policies/
COPY proof1b2c-staging/alembic.ini /app/alembic.ini
COPY proof_1b_2c/ /app/proof_1b_2c/
RUN chmod -R a+rX /opt/cognic /app/alembic.ini /app/proof_1b_2c
ENV COGNIC_PACK_ATTESTATION_ROOT_PATH=/opt/cognic/pack-attestations \
    COGNIC_TRUST_ROOT_PREFIX=/opt/cognic/trust-roots \
    COGNIC_PLUGIN_ALLOWLIST_PATH=/opt/cognic/policies/plugin_allowlist.json
ENV PYTHONPATH=/app
USER cognic
CMD ["sh","-c","exec uvicorn proof_1b_2c.proof_app:create_proof_app --factory --host 0.0.0.0 --port 8000"]
```

> The `BASE_IMAGE` default `cognic-agentos:proof1b2-base` is the `--target default-adapters` build; the runner builds it (Task 10). It already packages `policies/` + `alembic.ini` at the image level (#98), but the staging copies override with the proof-specific allow-list + the released pack — identical to Proof 1b-2.

- [ ] **Step 5: Run the app test, watch pass. Step 6: Commit** (`feat(proof-1b-2c): proof AgentOS image + fixed-actor app`).

---

## Task 8: DB + Vault seed scripts

**Files:** Create `infra/proof-1b-2c/seed-db.sh`, `infra/proof-1b-2c/seed-vault.sh`; Test `tests/unit/proof_1b_2c/test_seeds.py`.

- [ ] **Step 1: Failing test**:

```python
from pathlib import Path
DB = Path("infra/proof-1b-2c/seed-db.sh").read_text()
VAULT = Path("infra/proof-1b-2c/seed-vault.sh").read_text()


def test_db_seeds_oracle_pack_override_and_allowlist():
    assert "cognic-tool-oracle-schema" in DB and "http://10.96.0.51:8765/mcp" in DB
    assert "10.96.0.51" in DB and "proof-1b-2c" in DB


def test_vault_as_allowlist_trailing_slash_and_oauth():
    assert "192.88.99.9:9000/" in VAULT  # exact-string compare needs the slash
    assert "mcp-as-allowlist" in VAULT and "mcp-oauth" in VAULT and "proof-1b-2c" in VAULT
```

- [ ] **Step 2: Run, watch fail. Step 3: Implement.** `seed-db.sh` mirrors `infra/proof-1b-2/seed-db.sh` with `T="proof-1b-2c"`, `URL="http://10.96.0.51:8765/mcp"`, `IP="10.96.0.51"`, `pack_id='cognic-tool-oracle-schema'`. `seed-vault.sh` mirrors `infra/proof-1b-2/seed-vault.sh` with `T="proof-1b-2c"` (same AS host/issuer `192.88.99.9:9000`, same `{"servers":["${AS}/"]}` trailing-slash form, same `mcp-oauth/$ASHOST` creds).

- [ ] **Step 4: Run, watch pass. Step 5: Commit** (`feat(proof-1b-2c): DB + Vault seed scripts`).

---

## Task 9: Helm overlay + migrate Job

**Files:** Create `infra/proof-1b-2c/proof-1b-2c-values.yaml`, `infra/proof-1b-2c/migrate-job.yaml`; Test `tests/unit/proof_1b_2c/test_values.py`.

- [ ] **Step 1: Failing test**:

```python
from pathlib import Path
import yaml
V = yaml.safe_load(Path("infra/proof-1b-2c/proof-1b-2c-values.yaml").read_text())
MJ = Path("infra/proof-1b-2c/migrate-job.yaml").read_text()


def test_values_prod_profile_migrations_off_proof_tag():
    assert V["image"]["tag"] == "proof1b2c"
    assert V["runtimeProfile"] == "prod" and V["migrations"]["enabled"] is False


def test_migrate_job_has_image_slot():
    assert "__AGENTOS_IMAGE__" in MJ
```

- [ ] **Step 2: Run, watch fail. Step 3: Implement.** `proof-1b-2c-values.yaml` mirrors `infra/proof-1b-2/proof-1b-2-values.yaml`, changing only `image.tag: proof1b2c`. `migrate-job.yaml` is a verbatim copy of `infra/proof-1b-2/migrate-job.yaml`.

- [ ] **Step 4: Run, watch pass. Step 5: Commit** (`chore(proof-1b-2c): Helm overlay + non-hook migrate Job`).

---

## Task 10: The end-to-end runner

**Files:** Create `infra/proof-1b-2c/run-proof-1b-2c.sh`, `infra/proof-1b-2c/README.md`; Modify `.gitignore`; Test `tests/unit/proof_1b_2c/test_runner.py`.

- [ ] **Step 1: Failing test**:

```python
from pathlib import Path
R = Path("infra/proof-1b-2c/run-proof-1b-2c.sh").read_text()


def test_env_gated_and_skip_clean():
    assert "COGNIC_RUN_PROOF_1B2C" in R and "exit 0" in R


def test_uses_released_staging_not_local_build():
    assert "tests.integration.proof_1b_2c.stage_released_pack" in R
    assert "uv build" not in R  # released artifact only


def test_creates_seed_configmap_from_single_source_file():
    assert "create configmap oracle-xe-seed" in R
    assert "oracle-seed/seed_schema.sql" in R


def test_brings_up_and_waits_for_xe():
    assert "oracle-xe.yaml" in R and "app=oracle-xe" in R and "--for=condition=ready" in R


def test_bar1_allowlist_removed_delta_is_the_must_have_negative():
    assert "mcp_internal_host_allowlist" in R and "DELETE" in R
    assert "mcp_discovery_url_refused" in R and "refused" in R


def test_bar2_calls_describe_table_and_asserts_auth_ready():
    assert "describe_table" in R
    assert '"owner":"COGNIC"' in R and '"table":"EMPLOYEES"' in R
    assert "auth_ready" in R and "PROOF 1b-2c (BAR 2) PASS" in R


def test_optional_verifier_negative_is_env_gated():
    assert "COGNIC_PROOF_VERIFIER_NEGATIVE" in R
```

- [ ] **Step 2: Run, watch fail. Step 3: Implement** `run-proof-1b-2c.sh` by adapting `infra/proof-1b-2/run-proof-1b-2.sh` (read it first; keep `set -euo pipefail`, `die`, `pf_*`, `roll_and_wait`, `bar2_fail`, `cleanup`/`trap`). Exact changes:

1. Gate `COGNIC_RUN_PROOF_1B2C`; `CLUSTER=cognic-proof1b2c`; `NS=cognic-proof1b2c`; `PROOF_DIR=infra/proof-1b-2c`; `STAGING_DST="$PROOF_DIR/proof1b2c-staging"`; `PROOF_APP_SRC="tests/integration/proof_1b_2c"`; `PROOF_APP_DST="$PROOF_DIR/proof_1b_2c"`; images `cognic-agentos:proof1b2c` / base `cognic-agentos:proof1b2-base` (reused) / `cognic-proof-oracle-pack:1b2c` / `cognic-proof-as:1b2c`. Add `gh` to the preflight tool list.
2. **DELETE the `uv build` pack-rebuild step** (released artifact only).
3. **Staging:** `uv run python -m tests.integration.proof_1b_2c.stage_released_pack "$STAGING_DST"` (downloads + digest-verifies + arranges directly into the build context). `cleanup()` removes `$STAGING_DST` + `$PROOF_APP_DST` + `$PROOF_DIR/_local_as.py`.
4. **Images:** build base (`--target default-adapters`); `cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"`; build `Dockerfile.agentos-proof` (context `$PROOF_DIR`); build `Dockerfile.oracle-pack` (context `$PROOF_DIR` — reads `proof1b2c-staging/wheel/`); `cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"` then build `Dockerfile.as` (context `$PROOF_DIR`).
5. **kind create + load** the 3 proof images + the pre-pulled backends (mirror; reuse `_backend_images`). Pre-pull `gvenzl/oracle-xe:21-slim` + `busybox:1.36` too and `kind load` them.
6. **Backends + XE:** apply `backends.yaml`; **also** create the seed ConfigMap + apply XE early so its slow boot overlaps the rest:

```bash
kubectl -n "$NS" create configmap oracle-xe-seed \
  --from-file=seed_schema.sql="$PROOF_DIR/oracle-seed/seed_schema.sql" \
  --dry-run=client -o yaml | kubectl apply -n "$NS" -f -
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"
kubectl -n "$NS" wait --for=condition=available --timeout=300s deploy --all   # backends
kubectl -n "$NS" wait --for=condition=ready pod -l app=oracle-xe --timeout=600s  # XE first-boot
```

7. Seed Vault (`seed-vault.sh`); `helm install rel "$CHART" -f "$PROOF_DIR/proof-1b-2c-values.yaml"`; run the non-hook migrate Job (`sed __AGENTOS_IMAGE__`); apply `manifests/oracle-pack.yaml` + `manifests/auth-server.yaml`; `rollout status deploy/proof-oracle-pack` + `deploy/proof-as`.
8. Seed DB (`seed-db.sh`); `roll_and_wait`; `pf_start`.
9. **BAR 1** — identical structure to Proof 1b-2 retargeted to `pack_id=cognic-tool-oracle-schema`, IP `10.96.0.51`, tenant `proof-1b-2c`, route `…/servers/cognic-tool-oracle-schema/tools`. The allow-list-removed cold-restart delta (DELETE row → `roll_and_wait` → HTTP≠200 + `mcp_discovery_url_refused` in body + `discovery_status=refused` via `/system/plugins?tenant_id=proof-1b-2c`) is the **must-have negative**. Re-seed + cold restart for clean state. Print `BAR 1 PASS`.
10. **BAR 2** — `list_tools` 200; `call_tool` body `{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}` → 200 carrying the EMPLOYEES column metadata (grep a fixture column, e.g. `EMPLOYEE_ID` or `FULL_NAME` — **verify the exact `MCPHost.call_tool` success-response JSON shape at implementation time** and assert against it); `discovery_status=auth_ready` via `/system/plugins?tenant_id=proof-1b-2c`. Print `PROOF 1b-2c (BAR 2) PASS`. Use `bar2_fail` on any step.
11. **Optional verifier negative (env-gated, after BAR 2, before cleanup):**

```bash
if [[ "${COGNIC_PROOF_VERIFIER_NEGATIVE:-}" == "1" ]]; then
  echo "==> (optional) verifier negative — wrong audience must fail the pack's RS256 verifier"
  kubectl -n "$NS" set env deploy/proof-oracle-pack COGNIC_OAUTH_AUDIENCE=http://10.96.0.99:8765/mcp
  kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=180s
  roll_and_wait; pf_start
  NEG="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-oracle-schema/tools/call \
    -H 'Content-Type: application/json' \
    -d '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}' || true)"
  [ "$NEG" != "200" ] || die "verifier-negative: aud mismatch should fail, got 200"
  echo "  verifier-negative OK: aud mismatch rejected by the pack's RS256 verifier (HTTP $NEG)"
  kubectl -n "$NS" set env deploy/proof-oracle-pack COGNIC_OAUTH_AUDIENCE=http://10.96.0.51:8765/mcp
  roll_and_wait; pf_start
fi
```

`.gitignore`: add `infra/proof-1b-2c/proof1b2c-staging/` + `infra/proof-1b-2c/proof_1b_2c/` + `infra/proof-1b-2c/_local_as.py` (transient build-context copies). `README.md`: mirror `infra/proof-1b-2/README.md` (proof-only-binder caveat + `COGNIC_RUN_PROOF_1B2C=1 bash infra/proof-1b-2c/run-proof-1b-2c.sh` + the optional-negative note).

- [ ] **Step 4: Run, watch pass. Step 5: Full structural gate + commit**

```bash
uv run ruff check tests && uv run ruff format --check tests && uv run mypy tests
uv run pytest tests/unit/proof_1b_2c/ -q
git add infra/proof-1b-2c/run-proof-1b-2c.sh infra/proof-1b-2c/README.md .gitignore \
        tests/unit/proof_1b_2c/test_runner.py
git commit -m "feat(proof-1b-2c): end-to-end runner (BAR 1 + BAR 2 + optional verifier negative)"
```

---

## Task 11: Operator run + evidence + flip M3

**Files:** Modify `docs/VALIDATION-RESULTS.md`, `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md`.

**Operator-gated (live kind + Docker + Oracle XE) and token-gated per the per-action authorization rule — NOT run autonomously.**

- [ ] **Step 1: Pre-run review.** `uv run pytest tests/unit/proof_1b_2c/ -q` + `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests` all green. `gh release view v0.1.0 --repo bmzee/cognic-tool-oracle-schema` still shows the 9 assets.
- [ ] **Step 2: Run (operator host, on token).** `COGNIC_RUN_PROOF_1B2C=1 bash infra/proof-1b-2c/run-proof-1b-2c.sh` (optionally `COGNIC_PROOF_VERIFIER_NEGATIVE=1` too). Expect `BAR 1 PASS` then `PROOF 1b-2c (BAR 2) PASS`. On any Bar-2 failure the runner appends diagnostics to `docs/VALIDATION-RESULTS.md` + exits non-zero — capture, diagnose, fix; never redefine the proof downward.
- [ ] **Step 3: Record evidence** in `docs/VALIDATION-RESULTS.md` — a new "M3-E2c — deployed governed proof (date)" section: released artifact (repo + Release URL + wheel/pub digests), boot-time trust registration success, `discovery_status=auth_ready`, the `call_tool(describe_table)` result over `10.96.0.51`, the RS256/JWKS AS, the must-have allow-list-removed delta, and (if run) the verifier-audience negative. Honest posture notes (dev-grade AS keypair; proof-only binder).
- [ ] **Step 4: Flip M3** in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` (checkbox + evidence pointer). **Human-only release gate — do NOT flip without explicit authorization that the proof ran green.**
- [ ] **Step 5: Commit** (`docs(proof-1b-2c): record green deployed proof + flip M3`) on `feat/proof-1b-2c`; land the two plan docs (`docs/m3-e2b-plan`) + `feat/proof-1b-2c` to main.

---

## Self-Review

- **Spec coverage (#108 §6):** (1) released signed pack installed → Task 2 (download v0.1.0) + Task 7 (bake + pip-install for `discover()`); (2) boot-time trust registration → Task 7 staging (now the *correct* `policies/`+`alembic.ini` layout) + the unchanged `registry_boot` path, asserted live in Task 11; (3) `auth_ready` → BAR 2; (4) `call_tool(describe_table)` → BAR 2. ✓
- **All five review findings patched:** P1 import path → staging helper is the importable `tests/integration/proof_1b_2c/stage_released_pack.py`, run via `python -m …`, tests import normally (Tasks 2, 10). P1 staging layout → `arrange()` writes `policies/plugin_allowlist.json` + copies the repo `alembic.ini`, matching `Dockerfile.agentos-proof`'s `COPY` lines (Task 2 + grounded in the read of both files). P2 PyJWT → declared in `[dev]` with justification, lazy-imported (Task 1). P2 seed drift → eliminated at the root: single-source `oracle-seed/seed_schema.sql`, runner-created ConfigMap, no embedded copy (Task 4 + Task 10). P2 branch → plan docs on `docs/m3-e2b-plan`, impl on `feat/proof-1b-2c` off main, subagent task-text note (Global Constraints). ✓
- **Placeholder scan:** no `__SEED_SQL__` placeholder remains (eliminated with the embedded ConfigMap). `__AGENTOS_IMAGE__` is the existing sed slot. Mirror-with-deltas tasks (3/6/7/8/9/10) name the source file + the exact changes. ✓
- **Type/name consistency:** ClusterIP `10.96.0.51`, AS `192.88.99.9:9000`, tenant `proof-1b-2c`, pack `cognic-tool-oracle-schema`, scope `oracle_schema.read`, staging dir `proof1b2c-staging`, app pkg `proof_1b_2c`, image tags `:1b2c`/`proof1b2c`, server module `cognic_tool_oracle_schema.server` — consistent across tasks + pinned by the structural tests. `ProofActorBinder().bind(request=None)` matches the read source. ✓
- **Remaining OPEN verification (one, flagged, do not weaken the gate):** Task 2 Step 5 — the *released* attestation/in-toto bundle vs the boot resolver's ADR-016 contract for a downloaded pack. Resolve early (before the full kind run); if structurally incompatible, stop for a design decision. The Task-7 binder shape + the staging layout are now RESOLVED via the file reads.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-28-m3-e2c-deployed-oracle-schema-proof.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task (T1–T10), two-stage review, per-task commit token; T11 is the operator-gated live run + the M3 release-gate flip (separately authorized).
2. **Inline Execution** — execute T1–T10 in this session with checkpoints; T11 operator-gated.

Tasks 1, 2, 7 carry the real judgment (the RS256 AS + the PyJWT dep; the released-asset staging + the boot-resolver compatibility check; the proof image + the corrected staging layout); 3–6, 8–10 are mirror-with-deltas. T11 is human/operator-gated.
