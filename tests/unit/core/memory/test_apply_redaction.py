"""Sprint 11.5b T4 — pure _apply_redaction helper tests (no DB)."""

import pytest

from cognic_agentos.core.memory.storage import _apply_redaction


def test_redacts_nested_leaf_and_deep_copies():
    src = {"account": {"number": "1234", "holder": "A"}, "outcome": "approved"}
    out = _apply_redaction(src, ("account", "number"), "[REDACTED]")
    assert out == {"account": {"number": "[REDACTED]", "holder": "A"}, "outcome": "approved"}
    src_account = src["account"]
    assert isinstance(src_account, dict)
    assert src_account["number"] == "1234"  # original untouched (deep copy)


def test_object_replacement_is_legal():
    out = _apply_redaction({"balance": 99}, ("balance",), {"masked": True})
    assert out == {"balance": {"masked": True}}


def test_missing_key_raises_value_error():
    with pytest.raises(ValueError):
        _apply_redaction({"account": {}}, ("account", "number"), "x")


def test_non_container_midpath_raises_value_error():
    # "scalar" is not a mapping, so midpath traversal must raise ValueError
    with pytest.raises(ValueError):
        _apply_redaction({"account": "scalar"}, ("account", "number"), "x")


def test_empty_path_raises_value_error():
    with pytest.raises(ValueError):
        _apply_redaction({"a": 1}, (), "x")


def test_intermediate_segment_not_mapping_raises_value_error():
    # A 3-segment path whose INTERMEDIATE segment ("a") traverses a non-mapping
    # ("scalar") must raise at the intermediate hop — distinct from the
    # leaf-absent raise (the loop body, not the post-loop leaf check).
    with pytest.raises(ValueError):
        _apply_redaction({"a": "scalar"}, ("a", "b", "c"), "x")
