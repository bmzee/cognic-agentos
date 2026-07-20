#!/usr/bin/env python3
"""Verify signed skill reference SQL and question facts against the live seed."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_KINDS = frozenset({"golden", "adversarial", "refusal", "trigger_pos", "trigger_neg"})
_MARKER_PREFIX = "__COGNIC_GOLDEN_SEED__"


class GoldenSeedVerificationError(RuntimeError):
    """The corpus cannot be proven against the staged database."""


@dataclass(frozen=True)
class GoldenSeedCheck:
    check_id: str
    sql: str
    runs: int
    expected: tuple[str, ...] | None = None


@dataclass(frozen=True)
class _CorpusCase:
    case_id: str
    kind: str
    question: str
    reference_sql: str | None


def _read_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-standard JSON constant {value}")
            ),
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise GoldenSeedVerificationError(f"unreadable JSON input: {path.name}") from exc


def _load_corpus(path: Path) -> dict[str, _CorpusCase]:
    cases: dict[str, _CorpusCase] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise GoldenSeedVerificationError(f"unreadable corpus: {path.name}") from exc
    for line_number, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise GoldenSeedVerificationError(
                f"invalid corpus JSON at {path.name}:{line_number}"
            ) from exc
        if not isinstance(row, dict):
            raise GoldenSeedVerificationError(f"invalid corpus row at {path.name}:{line_number}")
        case_id = row.get("case_id")
        kind = row.get("kind")
        question = row.get("question")
        reference_sql = row.get("reference_sql")
        if (
            not isinstance(case_id, str)
            or not case_id
            or kind not in _KINDS
            or not isinstance(question, str)
            or not question
            or (reference_sql is not None and not isinstance(reference_sql, str))
        ):
            raise GoldenSeedVerificationError(f"invalid corpus row at {path.name}:{line_number}")
        if case_id in cases:
            raise GoldenSeedVerificationError(f"duplicate corpus case: {case_id}")
        if reference_sql is not None:
            _validate_select(reference_sql, f"reference:{case_id}")
        cases[case_id] = _CorpusCase(case_id, kind, question, reference_sql)
    if not cases:
        raise GoldenSeedVerificationError(f"empty corpus: {path.name}")
    return cases


def _validate_select(sql: str, owner: str) -> None:
    if not sql.lstrip().upper().startswith("SELECT ") or ";" in sql:
        raise GoldenSeedVerificationError(f"{owner} is not one read-only SELECT")


def load_checks(corpus_specs: tuple[str, ...], facts_path: Path) -> tuple[GoldenSeedCheck, ...]:
    corpora: dict[str, dict[str, _CorpusCase]] = {}
    checks: list[GoldenSeedCheck] = []
    for spec in corpus_specs:
        skill_id, separator, raw_path = spec.partition("=")
        if not separator or not skill_id or not raw_path or skill_id in corpora:
            raise GoldenSeedVerificationError("corpus arguments must be unique SKILL_ID=PATH pairs")
        cases = _load_corpus(Path(raw_path))
        corpora[skill_id] = cases
        checks.extend(
            GoldenSeedCheck(
                check_id=f"reference:{skill_id}:{case.case_id}",
                sql=case.reference_sql,
                runs=2,
            )
            for case in cases.values()
            if case.reference_sql is not None
        )

    payload = _read_json(facts_path)
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise GoldenSeedVerificationError("fact contract schema mismatch")
    fact_rows = payload.get("checks")
    if not isinstance(fact_rows, list):
        raise GoldenSeedVerificationError("fact contract checks must be a list")
    ordinal_by_case: dict[tuple[str, str], int] = {}
    for row in fact_rows:
        if not isinstance(row, dict):
            raise GoldenSeedVerificationError("invalid fact contract row")
        fact_skill_id = row.get("skill_id")
        case_id = row.get("case_id")
        kind = row.get("kind")
        question_contains = row.get("question_contains")
        sql = row.get("sql")
        expected = row.get("expected")
        if (
            not isinstance(fact_skill_id, str)
            or not isinstance(case_id, str)
            or kind not in _KINDS
            or not isinstance(question_contains, str)
            or not question_contains
            or not isinstance(sql, str)
            or not isinstance(expected, list)
            or not expected
            or not all(isinstance(value, str) for value in expected)
        ):
            raise GoldenSeedVerificationError("invalid fact contract row")
        case = corpora.get(fact_skill_id, {}).get(case_id)
        if case is None or case.kind != kind or question_contains not in case.question:
            raise GoldenSeedVerificationError(f"question fact drift: {fact_skill_id}:{case_id}")
        _validate_select(sql, f"fact:{fact_skill_id}:{case_id}")
        key = (fact_skill_id, case_id)
        ordinal_by_case[key] = ordinal_by_case.get(key, 0) + 1
        checks.append(
            GoldenSeedCheck(
                check_id=f"fact:{fact_skill_id}:{case_id}:{ordinal_by_case[key]}",
                sql=sql,
                runs=1,
                expected=tuple(expected),
            )
        )
    return tuple(checks)


def result_marker(
    check_id: str,
    run_index: int,
    edge: Literal["BEGIN", "END"],
) -> str:
    return f"{_MARKER_PREFIX}|{edge}|{check_id}|{run_index}"


def build_sqlplus_batch(checks: tuple[GoldenSeedCheck, ...]) -> str:
    lines = [
        "SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 32767 LONG 1000000",
        "SET LONGCHUNKSIZE 1000000 TRIMSPOOL ON TAB OFF VERIFY OFF ECHO OFF DEFINE OFF",
        "SET COLSEP |",
        "WHENEVER SQLERROR EXIT SQL.SQLCODE",
        "ALTER SESSION SET CONTAINER = FREEPDB1;",
    ]
    for check in checks:
        for run_index in range(1, check.runs + 1):
            lines.extend(
                (
                    f"PROMPT {result_marker(check.check_id, run_index, 'BEGIN')}",
                    f"{check.sql};",
                    f"PROMPT {result_marker(check.check_id, run_index, 'END')}",
                )
            )
    lines.append("EXIT")
    return "\n".join(lines) + "\n"


def parse_results(output: str) -> dict[tuple[str, int], tuple[str, ...]]:
    results: dict[tuple[str, int], tuple[str, ...]] = {}
    active: tuple[str, int] | None = None
    values: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith(f"{_MARKER_PREFIX}|BEGIN|"):
            if active is not None:
                raise GoldenSeedVerificationError("nested SQL result marker")
            _, _, check_id, raw_run = line.split("|", 3)
            active = (check_id, int(raw_run))
            values = []
        elif line.startswith(f"{_MARKER_PREFIX}|END|"):
            if active is None:
                raise GoldenSeedVerificationError("orphan SQL result marker")
            _, _, check_id, raw_run = line.split("|", 3)
            key = (check_id, int(raw_run))
            if key != active or key in results:
                raise GoldenSeedVerificationError("mismatched SQL result marker")
            results[key] = tuple(value for value in values if value)
            active = None
            values = []
        elif active is not None and line:
            values.append(line)
    if active is not None:
        raise GoldenSeedVerificationError("unterminated SQL result marker")
    return results


def verify_results(
    checks: tuple[GoldenSeedCheck, ...],
    results: dict[tuple[str, int], tuple[str, ...]],
) -> None:
    expected_keys = {
        (check.check_id, run_index) for check in checks for run_index in range(1, check.runs + 1)
    }
    if set(results) != expected_keys:
        raise GoldenSeedVerificationError("SQL result set is incomplete or carries extras")
    for check in checks:
        first = results[(check.check_id, 1)]
        if check.expected is None:
            if not first:
                raise GoldenSeedVerificationError(f"{check.check_id} returned no rows")
            if results[(check.check_id, 2)] != first:
                raise GoldenSeedVerificationError(f"{check.check_id} is not deterministic")
        elif first != check.expected:
            raise GoldenSeedVerificationError(f"{check.check_id} fact mismatch")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", action="append", required=True, dest="corpora")
    parser.add_argument(
        "--facts",
        type=Path,
        default=Path(__file__).with_name("golden_fact_checks.json"),
    )
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--docker-container")
    transport.add_argument("--kube-pod")
    parser.add_argument("--namespace")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        checks = load_checks(tuple(args.corpora), args.facts)
        if args.docker_container:
            command = [
                "docker",
                "exec",
                "-i",
                args.docker_container,
                "sqlplus",
                "-s",
                "/",
                "as",
                "sysdba",
            ]
        else:
            if not args.namespace:
                raise GoldenSeedVerificationError("--namespace is required with --kube-pod")
            command = [
                "kubectl",
                "-n",
                args.namespace,
                "exec",
                "-i",
                args.kube_pod,
                "--",
                "sqlplus",
                "-s",
                "/",
                "as",
                "sysdba",
            ]
        completed = subprocess.run(
            command,
            input=build_sqlplus_batch(checks),
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise GoldenSeedVerificationError("live SQL execution failed")
        verify_results(checks, parse_results(completed.stdout))
    except GoldenSeedVerificationError as exc:
        print(f"golden seed verification refused: {exc}", file=sys.stderr)
        return 2
    reference_count = sum(check.expected is None for check in checks)
    fact_count = len(checks) - reference_count
    print(
        f"golden seed verification PASS: {reference_count} reference queries x2; "
        f"{fact_count} question facts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
