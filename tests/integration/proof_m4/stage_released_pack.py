"""Download + stage the RELEASED, signed cognic-tool-oracle-schema@v0.1.0 for the
M4 (operator-install) boot-trust gate. Released artifact only (acceptance criterion #1) — never a
local rebuild. Produces the same staging-tree shape stage_trust_inputs.py emits
(so Dockerfile.agentos-proof consumes it identically), but by DOWNLOAD not build.
From repo root: python -m tests.integration.proof_m4.stage_released_pack <out>."""

from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# tests/integration/proof_m4/stage_released_pack.py -> parents[3] == repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]

PACK_ID = "cognic-tool-oracle-schema"
VERSION = "0.1.0"
WHEEL = f"cognic_tool_oracle_schema-{VERSION}-py3-none-any.whl"
RELEASE_TAG = "v0.1.0"
RELEASE_REPO = "bmzee/cognic-tool-oracle-schema"
ATTESTATIONS = (
    "cosign.sig",
    "bundle.sigstore",
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
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
    cmd = [
        "gh",
        "release",
        "download",
        RELEASE_TAG,
        "--repo",
        RELEASE_REPO,
        "--dir",
        str(dst_dir),
        "--clobber",
    ]
    max_attempts = 5
    for attempt in range(1, max_attempts + 1):
        try:
            subprocess.run(cmd, check=True)
            break
        except subprocess.CalledProcessError:
            if attempt == max_attempts:
                raise
            print(
                f"gh release download failed (attempt {attempt}/{max_attempts}); retrying in 3s",
                file=sys.stderr,
            )
            time.sleep(3)
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
    policies = dst / "policies"
    policies.mkdir(parents=True)
    (policies / "plugin_allowlist.json").write_text(json.dumps(_ALLOWLIST), encoding="utf-8")
    shutil.copy2(_REPO_ROOT / "alembic.ini", dst / "alembic.ini")
    for p in dst.rglob("*"):
        p.chmod(
            p.stat().st_mode
            | stat.S_IRGRP
            | stat.S_IROTH
            | ((stat.S_IXGRP | stat.S_IXOTH) if p.is_dir() else 0)
        )


def main(dst: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        arrange(download(Path(tmp)), Path(dst))
    print(f"staged released {PACK_ID}@{VERSION} -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1])
