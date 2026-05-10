"""Sprint-7A2 T7+T8 architecture test — hook-dispatcher payload-never-logged.

Per the plan-of-record's Doctrine Lock E (payload-contents-never-
logged invariant) + the Sprint-7A2 T7+T8 review watchpoints:

  The ``payload`` argument is opaque bytes; the dispatcher computes
  ``hashlib.sha256(payload).hexdigest()`` for the audit row's
  ``policy_input_digest`` field but NEVER includes the payload bytes
  themselves in any audit / decision-history / log line.

This test is the **mechanical guardrail** for that invariant. It
walks the AST of every Python file under
``src/cognic_agentos/packs/hooks/`` and refuses any of the dangerous
shapes that would let payload bytes leak into a log / print /
stringification path.

Sprint-7A2 T8 extension: ``packs/hooks/dlp_integration.py`` (the
runtime DLP scan adapter) joins the swept module set automatically
via the rglob discovery in :func:`_hook_modules`. The DLPGuard wraps
the dispatcher with per-pack hook selection + closed-enum
``DLPRefusalReason`` — same payload-never-logged invariant applies
because DLPGuard inherits the ``policy_input_digest`` from the
dispatcher and never re-handles raw payload bytes.

The taxonomy of refused shapes (flat ban, tight allow-list):

  1. ``print(...)`` calls ANYWHERE in the dispatcher module — even
     without payload-name reference. The dispatcher is not a debug
     utility; legitimate diagnostic output flows through the audit
     callback.
  2. ``logging.<getLogger,info,debug,warning,error,critical,...>(...)``
     calls. Same rationale — audit emission is the single
     observability path.
  3. ``logger.<info,debug,warning,error,critical,exception,...>(...)``
     attribute-call shapes (``self._logger.info(...)`` etc.).
  4. ``f"...{payload}..."`` — any f-string formatted-value referencing
     the ``payload`` Name.
  5. ``str(payload)`` / ``repr(payload)`` / ``format(payload)`` —
     stringification of the payload bytes.
  6. ``payload.decode(...)`` — decoding the payload to text where it
     could land in a log line.
  7. ``"%s" % payload`` / ``"...".format(payload)`` — old-style and
     str.format formatting.

Allowed (NOT refused):

  * ``hashlib.sha256(payload)`` / ``hashlib.sha256(payload).hexdigest()``
    — the digest computation that is the loadbearing reason payload
    enters the dispatcher at all.
  * ``len(payload)`` — size check for the unscannable budget.
  * Passing payload as positional / keyword argument to
    ``Hook.invoke`` / ``hook.invoke`` / ``instance.invoke`` —
    delegation to the hook subclass (which has its own
    payload-never-logged discipline pinned by the SDK seam +
    pack-author convention).
  * Assignment / re-assignment (``current_payload = payload``;
    ``current_payload = result.redacted_payload``).
  * Comparing length / boolean (``if len(payload) > ...:``).

The companion runtime regression at
``tests/unit/packs/hooks/test_hook_dispatcher.py`` exercises every
closed-enum failure path; both must hold for the threat model to be
intact.
"""

from __future__ import annotations

import ast
import pathlib
from collections.abc import Callable, Iterable

import pytest

# ``logger.info(...)`` / ``logging.info(...)`` etc. — both module-call
# and attribute-call shapes.
_BANNED_LOG_ATTRS: frozenset[str] = frozenset(
    {
        "info",
        "debug",
        "warning",
        "warn",
        "error",
        "critical",
        "exception",
        "log",
        "fatal",
    }
)

#: Module-name roots that are themselves the logging surface (calls
#: like ``logging.info`` / ``logging.getLogger`` / ``logging.error``
#: are all banned).
_BANNED_LOGGING_MODULE_NAMES: frozenset[str] = frozenset({"logging", "structlog", "loguru"})

#: Builtin call names that, when invoked on ``payload``, leak
#: stringified bytes into a logger.
_BANNED_BUILTIN_CALLS_ON_PAYLOAD: frozenset[str] = frozenset({"str", "repr", "format", "ascii"})


def _hook_modules() -> list[pathlib.Path]:
    """Every ``.py`` file under ``src/cognic_agentos/packs/hooks/``."""
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    pkg = repo_root / "src" / "cognic_agentos" / "packs" / "hooks"
    return sorted(p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts)


def _walk_module(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


# ---------------------------------------------------------------------------
# Visitor — refuse banned shapes
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def _modules() -> list[pathlib.Path]:
    return _hook_modules()


def test_no_print_call_in_hook_modules(_modules: list[pathlib.Path]) -> None:
    """Refuse any ``print(...)`` call. The dispatcher does not log to
    stdout/stderr; observability flows through audit emission."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "print":
                    pytest.fail(
                        f"{path}:{node.lineno} — print() call in hook module; "
                        f"the dispatcher must not write to stdout/stderr "
                        f"(per Doctrine Lock E payload-never-logged invariant)."
                    )


def test_no_logging_module_calls_in_hook_modules(
    _modules: list[pathlib.Path],
) -> None:
    """Refuse any ``logging.*`` / ``structlog.*`` / ``loguru.*`` call.
    Even calls that don't touch payload directly (``logging.info("x")``)
    are banned — the dispatcher routes ALL observability through the
    audit-callback layer that has the payload-never-logged discipline
    pinned by its own AST regressions."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute):
                # ``logging.info(...)`` — root of attribute chain is a
                # banned-module Name.
                root = _attribute_chain_root(func)
                if isinstance(root, ast.Name) and root.id in _BANNED_LOGGING_MODULE_NAMES:
                    pytest.fail(
                        f"{path}:{node.lineno} — banned logging-module call "
                        f"({root.id}.{func.attr}). The dispatcher routes "
                        f"observability through the audit-callback layer "
                        f"only."
                    )


def test_no_logger_attribute_calls_in_hook_modules(
    _modules: list[pathlib.Path],
) -> None:
    """Refuse ``self._logger.info(...)`` / ``logger.warning(...)`` /
    similar attribute-call shapes. Tightest gate against ad-hoc
    diagnostic logging that could embed payload."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _BANNED_LOG_ATTRS:
                # Heuristic: any ``X.info(...)`` / ``X.error(...)`` style
                # call that isn't on a clearly-not-logger object.
                # Since the dispatcher module doesn't legitimately call
                # ``thing.info`` on anything (no objects with an
                # ``info`` method appear in the design), this flat ban
                # is safe. If a future module needs ``something.info``
                # for non-logging purposes, the allow-list goes here.
                pytest.fail(
                    f"{path}:{node.lineno} — banned ``.{func.attr}(...)`` "
                    f"call (looks like a logger). The dispatcher routes "
                    f"observability through the audit-callback layer only."
                )


def test_no_payload_in_fstrings(_modules: list[pathlib.Path]) -> None:
    """Refuse any f-string formatted-value that references the
    ``payload`` Name. F-strings are a common stringification leak
    vector."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            for value in node.values:
                if not isinstance(value, ast.FormattedValue):
                    continue
                if _expr_references_name(value.value, "payload"):
                    pytest.fail(
                        f"{path}:{node.lineno} — f-string references "
                        f"`payload` (stringification leak vector)."
                    )


def test_no_stringification_calls_on_payload(
    _modules: list[pathlib.Path],
) -> None:
    """Refuse ``str(payload)`` / ``repr(payload)`` / ``format(payload)``
    / ``ascii(payload)`` — direct stringification."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in _BANNED_BUILTIN_CALLS_ON_PAYLOAD:
                for arg in node.args:
                    if _expr_references_name(arg, "payload"):
                        pytest.fail(
                            f"{path}:{node.lineno} — banned ``{func.id}(payload)`` "
                            f"call (stringification leak vector)."
                        )


def test_no_payload_decode_calls(_modules: list[pathlib.Path]) -> None:
    """Refuse ``payload.decode(...)`` — decoding bytes to text where
    it could land in a log line. Hashing is the only allowed payload
    consumption inside the dispatcher."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "decode"
                and isinstance(func.value, ast.Name)
                and func.value.id == "payload"
            ):
                pytest.fail(
                    f"{path}:{node.lineno} — banned ``payload.decode(...)`` "
                    f"call. Bytes-to-text conversion is a stringification "
                    f"leak vector."
                )


def test_no_old_style_format_with_payload(
    _modules: list[pathlib.Path],
) -> None:
    """Refuse ``"%s" % payload`` and similar Mod-formatting that uses
    payload as the right operand."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp):
                continue
            if not isinstance(node.op, ast.Mod):
                continue
            if (
                isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and _expr_references_name(node.right, "payload")
            ):
                pytest.fail(
                    f'{path}:{node.lineno} — banned ``"..." % payload`` '
                    f"old-style formatting (stringification leak)."
                )


def test_no_str_format_with_payload(
    _modules: list[pathlib.Path],
) -> None:
    """Refuse ``"...".format(payload)`` style calls where payload is
    an argument."""
    for path in _modules:
        tree = _walk_module(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "format"
                and isinstance(func.value, ast.Constant)
                and isinstance(func.value.value, str)
            ):
                for arg in node.args:
                    if _expr_references_name(arg, "payload"):
                        pytest.fail(
                            f"{path}:{node.lineno} — banned "
                            f'``"...".format(payload)`` (stringification '
                            f"leak)."
                        )


def test_dispatcher_module_exists(_modules: list[pathlib.Path]) -> None:
    """Sanity check: the regression must run against the actual
    dispatcher module (not silently no-op when packs/hooks/ is empty)."""
    names = {p.name for p in _modules}
    assert "dispatcher.py" in names, (
        "tests/architecture/test_hook_payload_never_logged.py expected "
        "src/cognic_agentos/packs/hooks/dispatcher.py to exist; not found. "
        "If you renamed/removed the dispatcher, update this regression's "
        "module discovery."
    )


def test_dlp_integration_module_exists(_modules: list[pathlib.Path]) -> None:
    """Sprint-7A2 T8 — sanity check that dlp_integration.py is also
    swept. DLPGuard wraps the dispatcher's per-pack selector with the
    data-governance pre/post phase semantics; the same payload-never-
    logged invariant applies. Without this assertion, a future rename
    of dlp_integration.py could silently degrade the threat model."""
    names = {p.name for p in _modules}
    assert "dlp_integration.py" in names, (
        "tests/architecture/test_hook_payload_never_logged.py expected "
        "src/cognic_agentos/packs/hooks/dlp_integration.py to exist; not "
        "found. If you renamed/removed the DLP integration adapter, update "
        "this regression's module discovery."
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _attribute_chain_root(node: ast.AST) -> ast.AST:
    """Walk to the leftmost root of an Attribute chain.
    ``a.b.c.d`` → ``a`` (a Name node)."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return node


def _expr_references_name(expr: ast.AST, target: str) -> bool:
    """True if ``expr`` (or any Name descendant) is the ``target``
    identifier. Used to detect ``payload`` references inside
    sub-expressions (e.g., the formatted-value of an f-string)."""
    return any(isinstance(sub, ast.Name) and sub.id == target for sub in _walk_iter(expr))


def _walk_iter(node: ast.AST) -> Iterable[ast.AST]:
    """Yield ``node`` and every AST descendant (depth-first)."""
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _walk_iter(child)


# ---------------------------------------------------------------------------
# Self-tests — prove each AST check actually fires on a known-bad input.
#
# Without these, a regression that silently no-ops (e.g., a typo in a
# banned-name set, or a visitor that walks the wrong AST shape) would
# pass the file-walking tests vacuously and the threat model would
# silently degrade. Each self-test exercises ONE banned shape against
# an in-memory AST and asserts the corresponding detector returns a
# non-empty violation set.
# ---------------------------------------------------------------------------


def _detect_print(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "print":
                found.append(node.lineno)
    return found


def _detect_logging_module_call(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            root = _attribute_chain_root(func)
            if isinstance(root, ast.Name) and root.id in _BANNED_LOGGING_MODULE_NAMES:
                found.append(node.lineno)
    return found


def _detect_logger_attr_call(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _BANNED_LOG_ATTRS:
            found.append(node.lineno)
    return found


def _detect_payload_in_fstring(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            if _expr_references_name(value.value, "payload"):
                found.append(node.lineno)
    return found


def _detect_stringification_on_payload(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in _BANNED_BUILTIN_CALLS_ON_PAYLOAD:
            for arg in node.args:
                if _expr_references_name(arg, "payload"):
                    found.append(node.lineno)
    return found


def _detect_payload_decode(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "decode"
            and isinstance(func.value, ast.Name)
            and func.value.id == "payload"
        ):
            found.append(node.lineno)
    return found


def _detect_old_style_format_with_payload(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.BinOp):
            continue
        if not isinstance(node.op, ast.Mod):
            continue
        if (
            isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and _expr_references_name(node.right, "payload")
        ):
            found.append(node.lineno)
    return found


def _detect_str_format_with_payload(tree: ast.AST) -> list[int]:
    found: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "format"
            and isinstance(func.value, ast.Constant)
            and isinstance(func.value.value, str)
        ):
            for arg in node.args:
                if _expr_references_name(arg, "payload"):
                    found.append(node.lineno)
    return found


@pytest.mark.parametrize(
    ("source", "detector"),
    [
        # Each (bad-code-snippet, detector) pair — the snippet MUST
        # produce a non-empty violation list, proving the detector
        # actually catches the shape it's named for.
        (
            "def f():\n    print('hi')\n",
            _detect_print,
        ),
        (
            "import logging\ndef f():\n    logging.info('hi')\n",
            _detect_logging_module_call,
        ),
        (
            "def f(self):\n    self._logger.info('hi')\n",
            _detect_logger_attr_call,
        ),
        (
            "def f(payload):\n    x = f'{payload!r}'\n",
            _detect_payload_in_fstring,
        ),
        (
            "def f(payload):\n    x = str(payload)\n",
            _detect_stringification_on_payload,
        ),
        (
            "def f(payload):\n    x = repr(payload)\n",
            _detect_stringification_on_payload,
        ),
        (
            "def f(payload):\n    x = payload.decode()\n",
            _detect_payload_decode,
        ),
        (
            "def f(payload):\n    x = '%s' % payload\n",
            _detect_old_style_format_with_payload,
        ),
        (
            "def f(payload):\n    x = '{}'.format(payload)\n",
            _detect_str_format_with_payload,
        ),
    ],
)
def test_ast_detector_catches_known_bad_input(
    source: str, detector: Callable[[ast.AST], list[int]]
) -> None:
    """Self-test: run each detector against a known-bad code snippet
    and confirm at least one violation is reported. Without this,
    a typo in a banned-name set would silently degrade the threat
    model without breaking any of the file-walking tests."""
    tree = ast.parse(source)
    violations = detector(tree)
    assert violations, (
        "AST detector " + detector.__name__ + " did not catch the known-bad fixture; "
        "the threat model is silently degraded."
    )


def test_ast_detector_does_not_false_positive_on_clean_input() -> None:
    """Self-test: a benign code snippet (no banned shapes) MUST NOT
    trigger any of the detectors. Catches the symmetric failure
    mode where a detector is too aggressive and refuses legitimate
    code."""
    source = (
        "import hashlib\n"
        "def f(payload):\n"
        "    digest = hashlib.sha256(payload).hexdigest()\n"
        "    size = len(payload)\n"
        "    return (digest, size)\n"
    )
    tree = ast.parse(source)
    for detector in (
        _detect_print,
        _detect_logging_module_call,
        _detect_logger_attr_call,
        _detect_payload_in_fstring,
        _detect_stringification_on_payload,
        _detect_payload_decode,
        _detect_old_style_format_with_payload,
        _detect_str_format_with_payload,
    ):
        violations = detector(tree)
        assert violations == [], (
            "AST detector "
            + detector.__name__
            + " false-positived on a clean fixture: "
            + repr(violations)
        )
