from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO = Path(__file__).resolve().parents[3]
_ADAPTER = _REPO / "infra" / "proof-m85c" / "oracle-seed" / "adapt_sh_populate.py"

_TEXT_INDEX = (
    b"CREATE INDEX sup_text_idx ON supplementary_demographics(comments)\n"
    b"   INDEXTYPE IS ctxsys.context PARAMETERS('nopopulate');\n"
)
_LOAD_SETTING = b"SET LOAD BATCH_ROWS 10000 BATCHES_PER_COMMIT 1 DATE_FORMAT YYYY-MM-DD\n"
_LOAD_DIRECTIVES = tuple(
    f"LOAD {table} {table}.csv\n".encode()
    for table in (
        "costs",
        "customers",
        "promotions",
        "sales",
        "times",
        "supplementary_demographics",
    )
)


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _source() -> bytes:
    return b"".join(
        (
            b"PROMPT before\n",
            _LOAD_SETTING,
            b"PROMPT loader directives\n",
            *_LOAD_DIRECTIVES,
            b"PROMPT indexes\n",
            _TEXT_INDEX,
            b"CREATE INDEX costs_prod_bix ON costs (prod_id);\n",
        )
    )


def test_adaptation_removes_only_the_unsupported_closed_inventory() -> None:
    module = _load(_ADAPTER, "proof_m85e_adapt_sh_populate")

    adapted = module.adapt_sh_populate(_source())

    assert _TEXT_INDEX not in adapted
    assert _LOAD_SETTING not in adapted
    for directive in _LOAD_DIRECTIVES:
        assert directive not in adapted
    assert b"PROMPT before\n" in adapted
    assert b"PROMPT loader directives\n" in adapted
    assert b"PROMPT indexes\n" in adapted
    assert b"CREATE INDEX costs_prod_bix ON costs (prod_id);\n" in adapted


@pytest.mark.parametrize(
    "missing",
    (_TEXT_INDEX, _LOAD_SETTING, *_LOAD_DIRECTIVES),
    ids=(
        "oracle-text-index",
        "sqlcl-load-setting",
        *[item.decode().split()[1] for item in _LOAD_DIRECTIVES],
    ),
)
def test_adaptation_fails_loud_when_any_expected_archive_statement_is_absent(
    missing: bytes,
) -> None:
    module = _load(_ADAPTER, f"proof_m85e_adapt_missing_{abs(hash(missing))}")

    with pytest.raises(module.SampleAdaptationError, match="archive shape drift"):
        module.adapt_sh_populate(_source().replace(missing, b"", 1))


def test_adaptation_fails_loud_when_an_expected_statement_is_duplicated() -> None:
    module = _load(_ADAPTER, "proof_m85e_adapt_duplicate")

    with pytest.raises(module.SampleAdaptationError, match="archive shape drift"):
        module.adapt_sh_populate(_source() + _TEXT_INDEX)
