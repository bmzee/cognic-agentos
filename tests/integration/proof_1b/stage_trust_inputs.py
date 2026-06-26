"""Proof 1b-1 trust-input staging — reuse the real Proof-1a cosign/syft/grype
authoring toolchain to emit the image build-context trust inputs. From repo root:
    uv run python -m tests.integration.proof_1b.stage_trust_inputs <out_dir>
Writes <out>/{wheel/<whl>, pack-attestations/cognic-tool-search/0.1.0/...,
trust-roots/_default/cosign.pub, policies/plugin_allowlist.json}.
Requires uv/cosign/syft/grype/pip-licenses on PATH (same posture as
test_authoring_provision)."""

from __future__ import annotations

import json
import shutil
import stat
import sys
from pathlib import Path

from tests.integration.pack_loop._authoring import (
    build_sign_verify,
    provision_attestation_tree,
    write_cosign_pub,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_PACK = _REPO_ROOT / "examples" / "cognic-tool-search"
_ALLOWLIST = {"_default": ["cognic-tool-search"]}


def stage(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    artifacts = build_sign_verify(_PACK, key_dir=out_dir / "keys")
    (out_dir / "wheel").mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifacts.wheel, out_dir / "wheel" / artifacts.wheel.name)
    provision_attestation_tree(out_dir / "pack-attestations", artifacts)
    write_cosign_pub(out_dir / "trust-roots", artifacts.cosign_pub)
    # Gap 5: the default-adapters image carries the migration PACKAGE but not alembic.ini
    # (the script_location config), so a deployed `alembic upgrade head` can't find the
    # migrations dir. Bake the real repo alembic.ini into the proof image.
    shutil.copy2(_REPO_ROOT / "alembic.ini", out_dir / "alembic.ini")
    policies = out_dir / "policies"
    policies.mkdir(parents=True, exist_ok=True)
    (policies / "plugin_allowlist.json").write_text(json.dumps(_ALLOWLIST), encoding="utf-8")
    for p in out_dir.rglob("*"):
        p.chmod(
            p.stat().st_mode
            | stat.S_IRGRP
            | stat.S_IROTH
            | ((stat.S_IXGRP | stat.S_IXOTH) if p.is_dir() else 0)
        )


if __name__ == "__main__":
    stage(Path(sys.argv[1]).resolve())
