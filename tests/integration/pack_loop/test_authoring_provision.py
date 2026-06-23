"""Proof 1a Task 6 — real `agentos sign` output, provisioned into the resolver's
expected layout, is accepted by resolve_pack_attestations.

The author->runtime bridge: sign writes 7 files to <pack>/attestations/ and signs
the wheel IN PLACE in <pack>/dist/; the resolver wants all 8 co-located under
<root>/<dist>/<version>/. The provisioning copy (no renames) is the bridge.

Env-gated: requires the cosign/syft/grype toolchain. Fail-loud (not skip) when
COGNIC_RUN_PACK_LOOP_PROOF is set but the toolchain is missing.
"""

import datetime as dt
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.protocol.plugin_registry import PluginRegistry

_PROOF = os.environ.get("COGNIC_RUN_PACK_LOOP_PROOF") == "1"
pytestmark = pytest.mark.skipif(
    not _PROOF, reason="set COGNIC_RUN_PACK_LOOP_PROOF=1 to run the proof"
)

_REQUIRED_BINS = ("cosign", "syft", "grype")


def _require_toolchain() -> None:
    missing = [b for b in _REQUIRED_BINS if shutil.which(b) is None]
    if missing:
        raise AssertionError(
            f"COGNIC_RUN_PACK_LOOP_PROOF=1 but missing toolchain: {missing}. "
            "Install cosign/syft/grype or unset the env to skip."
        )


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'pack_loop_authoring.db'}"
    eng = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=dt.datetime.now(dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def registry(engine: AsyncEngine) -> PluginRegistry:
    return PluginRegistry(audit_store=AuditStore(engine))


def test_real_sign_output_provisions_into_resolver_layout(
    tmp_path: Path, registry: PluginRegistry
) -> None:
    _require_toolchain()
    from cognic_agentos.protocol.pack_attestation_resolver import resolve_pack_attestations
    from tests.integration.pack_loop._authoring import (
        build_sign_verify,
        provision_attestation_tree,
        write_cosign_pub,
    )

    pack = Path(__file__).resolve().parents[3] / "examples" / "cognic-tool-search"
    trust_root = tmp_path / "trust-roots"
    att_root = tmp_path / "attestations"

    artifacts = build_sign_verify(pack, key_dir=tmp_path / "keys")
    write_cosign_pub(trust_root, artifacts.cosign_pub)
    base = provision_attestation_tree(att_root, artifacts)

    # The resolver accepts the assembled tree against a discovered pack record.
    pack_obj = next(
        p for p in registry.discover() if p.record.distribution_name == "cognic-tool-search"
    )
    att = resolve_pack_attestations(
        pack_obj,
        pack_attestation_root=att_root,
        cosign_trust_root=trust_root / "_default" / "cosign.pub",
    )
    assert att.cosign_signature_path == base / "cosign.sig"
    assert att.cosign_blob_path.suffix == ".whl"
    assert att.cosign_blob_path.parent == base
    assert len(att.sbom_signed_digest) == 64
