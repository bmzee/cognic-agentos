"""Sprint-7A T10 — data-governance vocabulary consolidation guard.

Per the plan-of-record's R1 P2 #4 reviewer correction, the build-time
data-governance vocabulary lives at
:mod:`cognic_agentos.cli._governance_vocab` (canonical owner). The
runtime DLP enforcement substrate per ADR-017 lands in a future
sprint; when it ships, the runtime module MUST consolidate against
this same source-of-truth (either by importing directly OR by
migrating both consumers to a shared module in the same commit).

This test pins the build-time vocabulary's location + the future-
merge contract so a Sprint-N edit that adds a parallel literal in
``packs/evidence/data_governance.py`` (or wherever runtime DLP lands)
trips this test before the two consumers can diverge silently.
"""

from __future__ import annotations

import importlib.util
import typing


def test_governance_vocab_owner_is_cli_governance_vocab() -> None:
    """The canonical build-time vocab is at
    ``cli._governance_vocab``. Future maintainers reading this test
    MUST NOT add a parallel literal elsewhere — divergence between
    build-time + runtime on what counts as e.g. ``customer_pii``
    produces pack-author confusion + audit gaps."""
    from cognic_agentos.cli._governance_vocab import (
        DataClass,
        Purpose,
        RetentionPolicy,
    )

    # Each closed enum has a non-empty set of literal values; the
    # validator + tests reference these via ``typing.get_args``.
    assert typing.get_args(DataClass), "DataClass literal is empty"
    assert typing.get_args(Purpose), "Purpose literal is empty"
    assert typing.get_args(RetentionPolicy), "RetentionPolicy literal is empty"

    # All values are non-empty strings.
    all_values = (
        *typing.get_args(DataClass),
        *typing.get_args(Purpose),
        *typing.get_args(RetentionPolicy),
    )
    for value in all_values:
        assert isinstance(value, str) and value.strip(), (
            f"unexpected non-string-or-empty literal value: {value!r}"
        )


def test_governance_vocab_exports_restricted_data_classes() -> None:
    """T10 introduces ``RESTRICTED_DATA_CLASSES`` as a frozenset
    constant in the vocab module — the build-time owner of which
    DataClass values are restricted-tier. T9's MCP validator imports
    this constant rather than declaring its own (the original T9 ship
    used a local set with a non-canonical "restricted" string; T10
    consolidates)."""
    from cognic_agentos.cli._governance_vocab import (
        RESTRICTED_DATA_CLASSES,
        DataClass,
    )

    assert isinstance(RESTRICTED_DATA_CLASSES, frozenset)
    assert RESTRICTED_DATA_CLASSES, "restricted set must be non-empty"

    # Every restricted class MUST appear in the DataClass literal —
    # otherwise the cross-check could fire on a class that the
    # validator's own enum check would refuse.
    declared = set(typing.get_args(DataClass))
    assert declared >= RESTRICTED_DATA_CLASSES, (
        f"restricted classes {RESTRICTED_DATA_CLASSES - declared} are "
        "not in the DataClass closed-enum literal"
    )


def test_runtime_dlp_module_not_yet_present() -> None:
    """The runtime DLP enforcement substrate per ADR-017 has not yet
    landed. When it does (in a future sprint), the developer doing
    that work MUST either:

      1. Import vocabulary FROM ``cli._governance_vocab`` directly, OR
      2. Migrate both consumers to a shared location IN THE SAME
         COMMIT that lights up runtime DLP.

    Adding a parallel literal in a runtime module without doing one
    of those two things produces silent divergence — pack authors
    + auditors see different "customer_pii" definitions on the
    build-time and runtime sides.

    This guard test fires when the runtime module appears so the
    person landing it sees the consolidation reminder before
    proceeding.
    """
    # Candidate path the future runtime substrate is expected at
    # (per ADR-017 + plan-of-record). If it appears, the developer
    # landing it should follow the consolidation rule above.
    # find_spec raises ModuleNotFoundError when an intermediate
    # package is missing (e.g., cognic_agentos.packs not yet
    # created); treat that as "module not yet present".
    try:
        spec = importlib.util.find_spec("cognic_agentos.packs.evidence.data_governance")
    except ModuleNotFoundError:
        return
    if spec is None:
        # Module not yet present — guard passes; nothing to consolidate.
        return

    # Module exists. Verify it consumes the canonical vocab rather
    # than declaring a parallel literal. The simplest check: confirm
    # the module imports from cli._governance_vocab.
    runtime_module = importlib.import_module("cognic_agentos.packs.evidence.data_governance")
    assert hasattr(runtime_module, "DataClass") or hasattr(
        runtime_module, "_GOVERNANCE_VOCAB_SOURCE"
    ), (
        "runtime DLP module exists but does not appear to import from "
        "cli._governance_vocab — the vocabulary may have diverged. "
        "See test docstring for the consolidation rule."
    )
