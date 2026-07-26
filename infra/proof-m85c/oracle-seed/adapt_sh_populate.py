#!/usr/bin/env python3
"""Adapt Oracle's digest-pinned SH populate script for the slim proof image."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


class SampleAdaptationError(RuntimeError):
    """The pinned archive no longer has the exact reviewed statement inventory."""


_REMOVALS = (
    (
        "Oracle Text index",
        b"CREATE INDEX sup_text_idx ON supplementary_demographics(comments)\n"
        b"   INDEXTYPE IS ctxsys.context PARAMETERS('nopopulate');\n",
    ),
    (
        "SQLcl LOAD setting",
        b"SET LOAD BATCH_ROWS 10000 BATCHES_PER_COMMIT 1 DATE_FORMAT YYYY-MM-DD\n",
    ),
    *tuple(
        (
            f"SQLcl LOAD directive for {table}",
            f"LOAD {table} {table}.csv\n".encode(),
        )
        for table in (
            "costs",
            "customers",
            "promotions",
            "sales",
            "times",
            "supplementary_demographics",
        )
    ),
)


def adapt_sh_populate(source: bytes) -> bytes:
    """Remove only statements unavailable in sqlplus + Oracle Free slim."""
    adapted = source
    for label, statement in _REMOVALS:
        if adapted.count(statement) != 1:
            raise SampleAdaptationError(f"archive shape drift at {label}")
        adapted = adapted.replace(statement, b"", 1)
    return adapted


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        source = args.path.read_bytes()
        args.path.write_bytes(adapt_sh_populate(source))
    except (OSError, SampleAdaptationError) as exc:
        print(f"Oracle SH sample adaptation refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
