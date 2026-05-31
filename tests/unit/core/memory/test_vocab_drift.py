# TEST-ONLY cross-module import — pins memory's local vocab lockstep to the
# cli canonical WITHOUT a runtime core->cli import (drift detector is test-only).
import ast
import pathlib
import typing

from cognic_agentos.cli._governance_vocab import (
    RESTRICTED_DATA_CLASSES as CliRestricted,
)
from cognic_agentos.cli._governance_vocab import (
    DataClass as CliDataClass,
)
from cognic_agentos.cli._governance_vocab import (
    Purpose as CliPurpose,
)
from cognic_agentos.core.memory.tiers import (
    RESTRICTED_DATA_CLASSES,
    DataClass,
    Purpose,
)


def test_dataclass_lockstep_with_cli():
    assert set(typing.get_args(DataClass)) == set(typing.get_args(CliDataClass))


def test_purpose_lockstep_with_cli():
    assert set(typing.get_args(Purpose)) == set(typing.get_args(CliPurpose))


def test_restricted_lockstep_with_cli():
    assert CliRestricted == RESTRICTED_DATA_CLASSES


def test_memory_module_does_not_import_cli_at_runtime():
    src = pathlib.Path("src/cognic_agentos/core/memory/tiers.py").read_text()
    tree = ast.parse(src)
    bad = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and (n.module or "").startswith("cognic_agentos.cli")
    ]
    assert not bad, "core/memory/tiers.py must not import cli/* at runtime (arrow violation)"
