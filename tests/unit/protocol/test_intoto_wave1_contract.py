"""ADR-016 in-toto Wave-1 contract: the signer's real
_build_intoto_layout_dict output is accepted by the runtime
_verify_intoto, and tampering it is refused. Cross-contract — imports
from BOTH cli/sign.py (author) and protocol/supply_chain.py (runtime);
no hand-built layout fixture.
"""

from __future__ import annotations

import json
import typing
from pathlib import Path

import pytest

from cognic_agentos.cli.sign import _build_intoto_layout_dict
from cognic_agentos.packs.lifecycle import PackKind
from cognic_agentos.protocol.supply_chain import (
    _INTOTO_PACK_KINDS,
    AGENTOS_INTOTO_LAYOUT_TYPE,
    IntotoTampered,
    SupplyChainPipeline,
)


def _real_layout() -> dict[str, typing.Any]:
    return _build_intoto_layout_dict(
        pack_id="cognic-tool-search",
        pack_version="0.1.0",
        pack_kind="tool",
        signing_identity="cosign:proof@example.com",
        artifact_paths=["cognic_tool_search-0.1.0-py3-none-any.whl"],
    )


def _write(tmp_path: Path, layout: dict[str, typing.Any]) -> Path:
    p = tmp_path / "intoto-layout.json"
    p.write_text(json.dumps(layout), encoding="utf-8")
    return p


def test_real_signer_output_is_accepted_by_runtime(tmp_path: Path) -> None:
    # The contract pin: real author output -> runtime verify, no raise.
    SupplyChainPipeline._verify_intoto(_write(tmp_path, _real_layout()))


def test_signer_declares_the_single_sourced_runtime_constant() -> None:
    # cli/sign.py emits exactly the _type the runtime accepts.
    assert _real_layout()["_type"] == AGENTOS_INTOTO_LAYOUT_TYPE
    assert AGENTOS_INTOTO_LAYOUT_TYPE == "in-toto-layout/v1-wave1-simplified"


def test_kind_tuple_matches_canonical_packkind() -> None:
    assert set(_INTOTO_PACK_KINDS) == set(typing.get_args(PackKind))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(pack_kind="malware"),
        lambda d: d.update(pack_kind=""),
        lambda d: d.update(pack_kind="  "),
        lambda d: d.pop("signing_identity"),
        lambda d: d.update(signing_identity="  "),
        lambda d: d.update(artifact_paths=[]),
        lambda d: d.update(artifact_paths=["ok", ""]),
        lambda d: d.update(artifact_paths="not-a-list"),
        lambda d: d.pop("pack_id"),
        lambda d: d.update(pack_version="   "),
    ],
)
def test_tampered_wave1_layout_is_refused(
    tmp_path: Path, mutate: typing.Callable[[dict[str, typing.Any]], object]
) -> None:
    layout = _real_layout()
    mutate(layout)
    with pytest.raises(IntotoTampered):
        SupplyChainPipeline._verify_intoto(_write(tmp_path, layout))


def test_full_layout_branch_preserved(tmp_path: Path) -> None:
    # A non-simplified layout (no AgentOS _type) still goes through the
    # steps+expires branch: valid passes, malformed raises.
    good = {"steps": [{"name": "build"}], "expires": "2030-01-01T00:00:00Z"}
    SupplyChainPipeline._verify_intoto(_write(tmp_path, good))
    bad = {"steps": [], "expires": "2030-01-01T00:00:00Z"}
    with pytest.raises(IntotoTampered):
        SupplyChainPipeline._verify_intoto(_write(tmp_path, bad))


def test_wrapped_simplified_layout_is_accepted(tmp_path: Path) -> None:
    # Statement-wrapped form: the runtime extracts `predicate` (the
    # simplified layout) BEFORE the _type branch, so a wrapped Wave-1
    # layout routes into the simplified branch + is accepted. Pins the
    # load-bearing branch placement (after predicate-extraction) — a
    # refactor moving the _type check ahead of extraction would break
    # this silently.
    wrapped = {
        "predicateType": "https://in-toto.io/Layout/v0.1",
        "predicate": _real_layout(),
    }
    SupplyChainPipeline._verify_intoto(_write(tmp_path, wrapped))


def test_non_agentos_type_falls_through_to_steps_branch(tmp_path: Path) -> None:
    # A bare layout with a non-matching string _type is NOT the AgentOS
    # simplified contract → falls through to the steps+expires branch →
    # refused fail-closed (no steps). Documents the routing contract.
    other = {"_type": "in-toto-layout/v2", "pack_id": "x"}
    with pytest.raises(IntotoTampered):
        SupplyChainPipeline._verify_intoto(_write(tmp_path, other))
