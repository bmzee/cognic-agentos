# tests/integration/pack_loop/_authoring.py
"""Build -> sign -> validate -> verify the example pack, then provision the
attestation tree into the resolver's expected <root>/<dist>/<version>/ layout.

`agentos sign --bundle` writes 7 attestations into <pack>/attestations/ and signs
the wheel in place in <pack>/dist/. The resolver expects all 8 artifacts
co-located under <root>/<dist_name>/<dist_version>/. provision_attestation_tree
performs that copy (no renames) — the author->runtime bridge Proof 1a validates.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

_DIST_NAME = "cognic-tool-search"
_DIST_VERSION = "0.1.0"
_ATTESTATION_FILES = (
    "cosign.sig",
    "bundle.sigstore",
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
)


@dataclass(frozen=True)
class Artifacts:
    wheel: Path
    attestations_dir: Path
    cosign_pub: Path


def _run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise AssertionError(
            f"{' '.join(cmd)} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )


def build_sign_verify(pack: Path, *, key_dir: Path) -> Artifacts:
    key_dir.mkdir(parents=True, exist_ok=True)
    # 1. cosign keypair. COSIGN_PASSWORD="" -> unattended (empty passphrase).
    cosign_env = {**os.environ, "COSIGN_PASSWORD": ""}
    _run(["cosign", "generate-key-pair"], cwd=key_dir, env=cosign_env)
    cosign_pub = key_dir / "cosign.pub"
    cosign_key = key_dir / "cosign.key"

    # 2. build the wheel into <pack>/dist/  (uv build — the `build` module is not installed)
    dist = pack / "dist"
    if dist.exists():
        shutil.rmtree(dist)
    _run(["uv", "build", "--wheel"], cwd=pack)
    wheels = list(dist.glob("*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"

    # 3. sign --bundle (real cosign + syft + grype + license + SLSA + in-toto).
    #    `agentos sign` has NO --key flag; it resolves the signing key from
    #    settings.signing_key_path == env COGNIC_SIGNING_KEY_PATH. cosign sign-blob
    #    reads the (encrypted) key, so COSIGN_PASSWORD must be set too.
    #
    #    `uv run --with pip-licenses`: the bundle path resolves a 4th tool
    #    (pip-licenses, the license auditor) up-front alongside cosign/syft/grype.
    #    pip-licenses is not a project dependency, so it is supplied ephemerally
    #    to this one subprocess via `--with` — NO pyproject.toml / uv.lock edit.
    #    cosign/syft/grype still resolve from the host PATH under `uv run`.
    #
    #    `agentos sign --bundle` ALSO writes [supply_chain].blob_path back into the
    #    pack's cognic-pack-manifest.toml (round-trip via tomli_w, which drops the
    #    file's comments). Snapshot the manifest before sign + restore it in the
    #    finally so the committed Task-3 manifest stays byte-for-byte pristine. The
    #    resolver reads the on-disk attestation tree, not the manifest, so the
    #    restore does not affect what this proof exercises.
    manifest_path = pack / "cognic-pack-manifest.toml"
    manifest_snapshot = manifest_path.read_bytes()
    sign_env = {**os.environ, "COGNIC_SIGNING_KEY_PATH": str(cosign_key), "COSIGN_PASSWORD": ""}
    try:
        _run(
            ["uv", "run", "--with", "pip-licenses", "agentos", "sign", "--bundle", str(pack)],
            env=sign_env,
        )
        # 4. validate against the now-populated attestation tree, then verify.
        #    `agentos verify` needs the trust root: --trust-root <cosign.pub> (the
        #    cosign PUBLIC key; the signing key above is the PRIVATE key).
        _run(["uv", "run", "agentos", "validate", str(pack)])
        _run(["uv", "run", "agentos", "verify", "--trust-root", str(cosign_pub), str(pack)])
    finally:
        manifest_path.write_bytes(manifest_snapshot)

    return Artifacts(wheel=wheels[0], attestations_dir=pack / "attestations", cosign_pub=cosign_pub)


def write_cosign_pub(trust_root: Path, cosign_pub: Path) -> Path:
    dest = trust_root / "_default" / "cosign.pub"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(cosign_pub.read_bytes())
    return dest


def provision_attestation_tree(att_root: Path, artifacts: Artifacts) -> Path:
    """Assemble <att_root>/<dist>/<version>/ with the 7 attestations + the wheel.
    No renames — the names already match the resolver exactly. THIS is the
    co-location bridge sign itself never performs (the recorded finding)."""
    base = att_root / _DIST_NAME / _DIST_VERSION
    base.mkdir(parents=True, exist_ok=True)
    for name in _ATTESTATION_FILES:
        src = artifacts.attestations_dir / name
        if src.exists():  # 4 required always present; 3 optional may or may not be
            shutil.copy2(src, base / name)
    shutil.copy2(artifacts.wheel, base / artifacts.wheel.name)
    return base
