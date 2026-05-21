"""#477 AC6/AC11 — the fixture-image path is unreachable from production.

Scans every src/ module: no import or textual reference to
`_FixtureOnlySandboxCatalog` or any of the 3 test-only env vars
(`COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES`,
`COGNIC_FIXTURE_RUNTIME_IMAGE_REF`, `COGNIC_FIXTURE_PROXY_IMAGE_REF`).
"""

import pathlib

_SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos"
_FORBIDDEN = (
    "_FixtureOnlySandboxCatalog",
    "fixture_catalog",
    "COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES",
    "COGNIC_FIXTURE_RUNTIME_IMAGE_REF",
    "COGNIC_FIXTURE_PROXY_IMAGE_REF",
)


def test_no_src_module_references_the_fixture_path() -> None:
    assert _SRC.is_dir(), f"src/ scan root not found: {_SRC}"
    offenders = []
    scanned = 0
    for path in _SRC.rglob("*.py"):
        scanned += 1
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN:
            if token in text:
                offenders.append(f"{path}: {token}")
    # A vacuous scan of 0 files would silently pass — guard against it.
    assert scanned > 0, f"no src/ modules scanned under {_SRC}"
    assert not offenders, "src/ must not reference the #477 test-only fixture path: " + "; ".join(
        offenders
    )
