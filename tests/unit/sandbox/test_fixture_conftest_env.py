"""#477 T5 — env-var read+validate tests for ``resolve_fixture_refs``.

The fixture-mode env-var read+validate is the testable logic behind the
conformance conftest's fixture-image wiring. ``resolve_fixture_refs``
returns ``None`` when the flag is unset (byte-identical default path),
returns the two validated digest-pinned refs when the flag + both ref
env vars are set, and fails fast with ``RuntimeError`` when the flag is
set but a ref is missing or malformed — no silent skip, no placeholder
fallback per the AGENTS.md production-grade rule.
"""

import pytest

from tests.conformance.sandbox.fixture_catalog import resolve_fixture_refs


def test_resolve_returns_none_when_flag_unset(monkeypatch):
    monkeypatch.delenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", raising=False)
    assert resolve_fixture_refs() is None


def test_resolve_returns_refs_when_flag_and_vars_set(monkeypatch):
    rt = "reg/x-runtime-fixture@sha256:" + "a" * 64
    px = "reg/x-proxy-fixture@sha256:" + "b" * 64
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.setenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", rt)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", px)
    assert resolve_fixture_refs() == (rt, px)


def test_resolve_fails_fast_when_flag_set_but_ref_missing(monkeypatch):
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.delenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", raising=False)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", "reg/p@sha256:" + "b" * 64)
    with pytest.raises(RuntimeError, match="COGNIC_FIXTURE_RUNTIME_IMAGE_REF"):
        resolve_fixture_refs()


@pytest.mark.parametrize(
    "bad_ref",
    [
        # malformed digest (valid repo, bad digest)
        "reg/x-runtime:tag-only",  # no @sha256: digest at all
        "reg/x-runtime@sha256:bad",  # digest far too short
        "reg/x-runtime@sha256:" + "a" * 63,  # 63 hex — off by one
        "reg/x-runtime@sha256:" + "A" * 64,  # uppercase — not lowercase hex
        "reg/x-runtime@sha256:" + "g" * 64,  # 'g' is not a hex digit
        # malformed repository (valid digest, bad repo shape)
        "@sha256:" + "a" * 64,  # empty repository part
        "/bad@sha256:" + "a" * 64,  # leading-slash repository
        "reg//x@sha256:" + "a" * 64,  # empty path component
    ],
)
def test_resolve_fails_fast_on_malformed_runtime_ref(monkeypatch, bad_ref):
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.setenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", bad_ref)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", "reg/p@sha256:" + "b" * 64)
    with pytest.raises(RuntimeError, match="digest-pinned"):
        resolve_fixture_refs()


@pytest.mark.parametrize(
    "bad_ref",
    [
        "reg/p@sha256:bad",  # malformed digest
        "reg/p@sha256:" + "z" * 64,  # non-hex digest
        "reg/p:tag-only",  # no digest at all
        "/bad@sha256:" + "b" * 64,  # malformed repository
    ],
)
def test_resolve_fails_fast_on_malformed_proxy_ref(monkeypatch, bad_ref):
    monkeypatch.setenv("COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES", "1")
    monkeypatch.setenv("COGNIC_FIXTURE_RUNTIME_IMAGE_REF", "reg/r@sha256:" + "a" * 64)
    monkeypatch.setenv("COGNIC_FIXTURE_PROXY_IMAGE_REF", bad_ref)
    with pytest.raises(RuntimeError, match="digest-pinned"):
        resolve_fixture_refs()
