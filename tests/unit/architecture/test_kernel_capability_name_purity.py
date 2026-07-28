"""The kernel names capabilities by CLASS, never by pack instance.

AgentOS is an OS-only platform: agents, tools and skills ship as separately
versioned pack repos. A kernel module that branches on a capability
IDENTIFIER therefore binds the platform to one deployment's pack — it works
for that pack and silently does nothing for every other, with no error.

That is not hypothetical. ``core/agent/loop.py`` compared
``call.name == "run_readonly_query"`` (a tool from ``cognic-tool-oracle-schema``)
to decide whether to record scope use in the end-of-run memory digest. Any pack
naming its query tool differently got NO scope tracking at all. The fix keyed
that decision on the dispatcher-resolved capability CLASS instead.

WHY THIS IS DELIBERATELY SMALL
------------------------------
Earlier versions of this guard resolved constants — module-level, function-
local, collection wrappers, lambda and parameter shadowing — so it could catch
``T = "pack_tool"; call.name == T``. That required modelling Python's lexical
scopes, and three successive adversarial reviews found the model wrong each
time: flattened lambda parentage, comprehension targets treated as
enclosing-scope bindings (Python 3 gives them their own scope), missing
parameter and ``match``-capture bindings, unvisited function defaults. Every
repair introduced a new false negative or false positive.

**So constant resolution was REMOVED.** This guard now flags one thing: a
branch on an identifier-shaped attribute against an **inline string literal**.
No scope maps, no binding census, no shadowing rules — nothing that requires
knowing where a name resolves. What remains is checkable by reading it.

The trade is small in practice. The defect this exists to catch, and its
realistic recurrence, is someone writing the obvious literal. An author who
routes the string through a constant already has a dozen cheaper evasions
below that this guard never claimed to catch.

**No soundness claim, no completeness claim.** It detects the forms its
self-tests demonstrate; a hit is a prompt for review, not proof of a defect.

DETECTED — each pinned by a self-test below:
  ``==`` / ``!=`` in either orientation · ``in`` / ``not in`` in either
  orientation · ``match``/``case`` including OR-patterns ·
  ``.startswith`` / ``.endswith`` · subscript (``call["name"]``) ·
  ``.get("name")`` · tuple/list/set displays written inline, and the DIRECT
  KEYS OF A DICT DISPLAY (``in {"x": h}``) — NOT ``.keys()``, not ``{**d}``.

NOT DETECTED — a partial list; assume it is incomplete:
  ANY constant indirection (``T = "x"; call.name == T``) · ``getattr`` ·
  ``operator.eq`` / ``operator.contains`` · an intermediate variable · the
  walrus form · attribute or imported constants · runtime concatenation ·
  ``.lower()`` / ``.casefold()`` normalisation · ``case "x" as y`` ·
  a TUPLE-subject match (``match (call.name, kind): case ("x", _)``).

FALSE POSITIVES ARE EXPECTED AND ARE THE ALLOW-LIST'S JOB. The attribute set
is deliberately broad, and the subscript / ``.get`` arms extend that to ANY
mapping keyed ``"name"`` — JSON payloads, manifests, telemetry. ``person
["name"] == "Alice"``, ``color.name == "RED"`` and ``thread.name ==
"MainThread"`` all fire by design. Precision comes from a human reviewing a
hit into ``_ALLOWED``, never from the walker guessing the receiver.

THE REAL GUARANTEE lives elsewhere; this file is third in line: (1) the
generic mechanism EXISTS — ``DispatchOutcome`` carries the dispatcher-resolved
``capability_class`` and ``scope_id``, so a caller no longer NEEDS a tool name
(the original defect existed because that affordance was missing); (2) the
exact-equality vocabulary parity tests in ``tests/unit/core/agent/test_loop.py``;
(3) this tripwire; (4) code review. Do not cite this file as proof the kernel
is pack-agnostic.

Built-ins (``dispatch._BUILTIN_NAMES``) are imported, never restated, so the
exemption cannot drift from the implementation — and they are exempted only
for capability-NAME attributes, never for ``pack_id`` / ``agent_id`` /
``skill_id``, where a built-in's name would be meaningless and is itself a
smell.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from cognic_agentos.core.agent.dispatch import _BUILTIN_NAMES

_KERNEL_ROOT = Path(__file__).resolve().parents[3] / "src" / "cognic_agentos"
_REPO_ROOT = _KERNEL_ROOT.parents[1]

#: Attributes that hold an identifier which MAY be a capability. Deliberately
#: broad — precision comes from the allow-list, not from guessing the receiver.
_IDENTIFIER_ATTRS = frozenset(
    {"name", "tool_name", "capability_ref", "skill_id", "pack_id", "agent_id"}
)

#: Attributes for which a built-in name is a legitimate literal. ``pack_id`` and
#: friends are excluded: a built-in is not a pack, so ``pack_id == "read_skill"``
#: must NOT be waved through.
_BUILTIN_EXEMPT_ATTRS = frozenset({"name", "tool_name", "capability_ref"})

#: String methods that branch on an identifier just as surely as ``==`` does.
_BRANCHING_METHODS = frozenset({"startswith", "endswith"})

#: ``cli/templates`` is scaffolding COPIED into a new pack repo — placeholder
#: identifiers there become the pack author's, not the kernel's.
_EXEMPT_PARTS = ("cli/templates/",)

#: REVIEWED legitimate branches: ``(repo-relative module, attribute, literal)``.
#: Every entry is a human decision that this identifier is kernel-owned or
#: belongs to a non-capability namespace. Adding a row is a review action.
_ALLOWED: frozenset[tuple[str, str, str]] = frozenset(
    {
        # SQLAlchemy dialect discrimination — a database vendor, not a capability.
        ("src/cognic_agentos/db/types.py", "name", "oracle"),
        # ``conn.dialect.name == "sqlite"`` — the F-S2a export snapshot helper
        # takes SQLite's implicit-BEGIN path; PG/Oracle use explicit
        # transactions. Reviewed 2026-07-28 at the K1/F-S2a merge (the first
        # cross-branch drift this tripwire caught live).
        ("src/cognic_agentos/core/conversation/read_model.py", "name", "sqlite"),
        (
            "src/cognic_agentos/db/migrations/versions/20260531_0006_memory.py",
            "name",
            "oracle",
        ),
        # Filesystem entry names inside supply-chain readers/parsers.
        ("src/cognic_agentos/cli/sign.py", "name", "vuln-scan.json"),
        # ``"-" in wheel.name`` — a hyphen-presence probe on a WHEEL FILENAME
        # while parsing PEP-427 name-version segments.
        ("src/cognic_agentos/cli/sign.py", "name", "-"),
        ("src/cognic_agentos/cli/verify.py", "name", "-"),
    }
)


def _kernel_modules() -> list[Path]:
    return sorted(
        path
        for path in _KERNEL_ROOT.rglob("*.py")
        if not any(part in path.as_posix() for part in _EXEMPT_PARTS)
    )


def _inline_strings(node: ast.AST | None) -> list[str]:
    """Inline string constants this expression denotes — NO name resolution.

    Constants, and tuple/list/set displays of constants. A bare ``ast.Name``
    resolves to nothing by design: resolving it is what required modelling
    Python scopes, and that modelling was wrong three reviews running.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return [value for element in node.elts for value in _inline_strings(element)]
    # Dict-KEY membership is semantically identical to set membership, and an
    # inline handler table before dispatch is a realistic shape.
    if isinstance(node, ast.Dict):
        return [value for key in node.keys for value in _inline_strings(key)]
    return []


def _identifier_attr(node: ast.AST | None) -> str | None:
    """The identifier-shaped attribute this expression reads, if any.

    Covers ``x.name``, ``x["name"]``, and ``x.name.startswith`` receivers.
    """
    if isinstance(node, ast.Attribute) and node.attr in _IDENTIFIER_ATTRS:
        return node.attr
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and node.slice.value in _IDENTIFIER_ATTRS
    ):
        return node.slice.value
    # ``row.get("name")`` — the dominant dict-payload idiom, and one method
    # call from the detected subscript form. Review found it live in the
    # kernel (``evaluation/skill_eval.py``, ``packs/storage.py``) while
    # appearing in NEITHER the detected nor the not-detected list.
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value in _IDENTIFIER_ATTRS
    ):
        return node.args[0].value
    return None


def _match_value_patterns(pattern: ast.pattern) -> list[ast.MatchValue]:
    """Flatten ``case "a"`` and the OR form ``case "a" | "b"``."""
    if isinstance(pattern, ast.MatchValue):
        return [pattern]
    if isinstance(pattern, ast.MatchOr):
        return [inner for alt in pattern.patterns for inner in _match_value_patterns(alt)]
    return []


def _identifier_branches(tree: ast.AST) -> list[tuple[int, str, str]]:
    """``(lineno, attribute, literal)`` for every DETECTED inline-literal branch.

    Detection covers exactly the Compare / match-case / branching-method
    shapes walked below. Inline-literal branches OUTSIDE those shapes (e.g.
    ``operator.eq(call.name, "pack_tool")``) are deliberately not returned;
    ``TestNotDetectedShapes`` pins each such documented limit.

    One flat walk. There is no scope handling because there is nothing to
    scope: only inline literals are considered, and an inline literal means
    the same thing wherever it appears.
    """
    found: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for index, op in enumerate(node.ops):
                left = node.left if index == 0 else node.comparators[index - 1]
                right = node.comparators[index]
                if not isinstance(op, ast.Eq | ast.NotEq | ast.In | ast.NotIn):
                    continue
                # BOTH orientations for every operator: ``x.name in {...}`` is
                # collection dispatch and ``"lit" in x.name`` is a substring
                # test, but ``"run_readonly_query" in call.name`` is exactly as
                # pack-specific as equality. Legitimate substring probes go
                # through the allow-list like anything else.
                for subject, other in ((left, right), (right, left)):
                    attr = _identifier_attr(subject)
                    if attr is None:
                        continue
                    found.extend((node.lineno, attr, lit) for lit in _inline_strings(other))
        elif isinstance(node, ast.Match):
            attr = _identifier_attr(node.subject)
            if attr is not None:
                for case in node.cases:
                    for pattern in _match_value_patterns(case.pattern):
                        found.extend(
                            (pattern.lineno, attr, lit) for lit in _inline_strings(pattern.value)
                        )
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _BRANCHING_METHODS:
                attr = _identifier_attr(func.value)
                if attr is not None:
                    for argument in node.args:
                        found.extend((node.lineno, attr, lit) for lit in _inline_strings(argument))
    return found


def _is_exempt(rel: str, attr: str, literal: str) -> bool:
    """Whether this branch is licensed: a kernel built-in, or reviewed.

    Factored out of the sweep so the ENFORCEMENT can be driven with synthetic
    input. Review found the previous shape untestable: deleting the exemption
    outright left every test green, because the only assertion about it
    checked frozenset CONTENTS and the parametrized rows exercised the walker,
    which never applies the exemption at all.
    """
    if literal in _BUILTIN_NAMES and attr in _BUILTIN_EXEMPT_ATTRS:
        return True
    return (rel, attr, literal) in _ALLOWED


def test_kernel_never_branches_on_an_unreviewed_capability_identifier() -> None:
    """Every DETECTED inline-literal identifier branch is a built-in or reviewed.

    "Detected" is load-bearing: the sweep enforces over what
    ``_identifier_branches`` returns; ``TestNotDetectedShapes`` pins the
    inline-literal shapes it deliberately does not.
    """
    violations: list[str] = []
    for path in _kernel_modules():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:  # pragma: no cover - a broken kernel file fails elsewhere
            pytest.fail(f"{path} is not parseable: {exc}")
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for lineno, attr, literal in _identifier_branches(tree):
            if _is_exempt(rel, attr, literal):
                continue
            # NOT "== {literal}": a hit may be ``in`` / ``.startswith`` /
            # ``match``. Review found the old wording misstated the code to
            # the one person who reads it — the engineer responding to it.
            violations.append(f"{rel}:{lineno} branches on .{attr} against {literal!r}")

    assert not violations, (
        "kernel modules must branch on capability CLASS, not on a pack's "
        "capability IDENTIFIER — an identifier branch serves one pack and "
        "silently no-ops for every other. If a branch below is legitimate, "
        "add it to _ALLOWED with a justifying comment (that IS the review "
        "record):\n  " + "\n  ".join(violations)
    )


class TestDetectedShapes:
    """Every entry in the docstring's DETECTED list, one row each.

    A DETECTED entry without a pin is an overclaim — that exact defect was
    found in review, where the list advertised ``not in`` and ``.endswith``
    while removing their support left the whole suite green.
    """

    @pytest.mark.parametrize(
        ("source", "literal"),
        [
            pytest.param('x = call.name == "pack_tool"\n', "pack_tool", id="eq"),
            pytest.param('x = "pack_tool" == call.name\n', "pack_tool", id="eq-reversed"),
            pytest.param('x = call.name != "pack_tool"\n', "pack_tool", id="noteq"),
            pytest.param('x = "pack_tool" != call.name\n', "pack_tool", id="noteq-reversed"),
            pytest.param('x = call.name in ("pack_tool",)\n', "pack_tool", id="in-tuple"),
            pytest.param('x = call.name in {"pack_tool"}\n', "pack_tool", id="in-set"),
            pytest.param('x = call.name in ["pack_tool"]\n', "pack_tool", id="in-list"),
            pytest.param('x = "pack_tool" in call.name\n', "pack_tool", id="in-reversed"),
            pytest.param('x = call.name not in ("pack_tool",)\n', "pack_tool", id="not-in"),
            pytest.param('x = "pack_tool" not in call.name\n', "pack_tool", id="not-in-reversed"),
            pytest.param(
                'match call.name:\n    case "pack_tool":\n        pass\n',
                "pack_tool",
                id="match-case",
            ),
            pytest.param(
                'match call.name:\n    case "a" | "pack_tool":\n        pass\n',
                "pack_tool",
                id="match-OR-pattern",
            ),
            pytest.param('x = call.name.startswith("pack_tool")\n', "pack_tool", id="startswith"),
            pytest.param('x = call.name.endswith("pack_tool")\n', "pack_tool", id="endswith"),
            pytest.param('x = call["name"] == "pack_tool"\n', "pack_tool", id="subscript"),
            pytest.param('x = call.get("name") == "pack_tool"\n', "pack_tool", id="dict-get"),
            pytest.param('x = spec.tool_name == "pack_tool"\n', "pack_tool", id="tool-name-attr"),
            pytest.param('x = row.skill_id == "pack_skill"\n', "pack_skill", id="skill-id-attr"),
            pytest.param('x = row.agent_id == "pack_agent"\n', "pack_agent", id="agent-id-attr"),
            pytest.param(
                'x = call.name in {"pack_tool": handler}\n', "pack_tool", id="in-dict-keys"
            ),
            pytest.param(
                'x = request.capability_ref == "srv/pack_tool"\n',
                "srv/pack_tool",
                id="capability-ref-attr",
            ),
            pytest.param(
                'x = request.pack_id == "read_skill"\n',
                "read_skill",
                id="builtin-literal-on-pack-id-still-detected",
            ),
        ],
    )
    def test_shape_is_detected(self, source: str, literal: str) -> None:
        # Assert the (attr, literal) PAIR: a regression that reports the right
        # literal against the WRONG attribute would pass a literal-only check.
        attr = "name"
        for candidate in ("capability_ref", "tool_name", "skill_id", "pack_id", "agent_id"):
            if candidate in source:
                attr = candidate
                break
        pairs = [(a, lit) for _lineno, a, lit in _identifier_branches(ast.parse(source))]
        assert (attr, literal) in pairs, f"advertised shape not detected: {source!r}"

    @pytest.mark.parametrize(
        ("rel", "attr", "literal", "exempt"),
        [
            pytest.param("x.py", "name", "read_skill", True, id="builtin-on-name-exempt"),
            pytest.param("x.py", "tool_name", "remember", True, id="builtin-on-tool-name-exempt"),
            pytest.param("x.py", "pack_id", "read_skill", False, id="builtin-on-pack-id-NOT"),
            pytest.param("x.py", "agent_id", "remember", False, id="builtin-on-agent-id-NOT"),
            pytest.param("x.py", "skill_id", "read_skill", False, id="builtin-on-skill-id-NOT"),
            pytest.param("x.py", "name", "pack_tool", False, id="non-builtin-not-exempt"),
            pytest.param(
                "src/cognic_agentos/db/types.py", "name", "oracle", True, id="allow-listed"
            ),
            pytest.param("other.py", "name", "oracle", False, id="allow-list-module-scoped"),
            pytest.param(
                "src/cognic_agentos/db/types.py",
                "pack_id",
                "oracle",
                False,
                id="allow-list-ATTRIBUTE-scoped",
            ),
            pytest.param(
                "src/cognic_agentos/db/types.py",
                "name",
                "postgresql",
                False,
                id="allow-list-LITERAL-scoped",
            ),
        ],
    )
    def test_exemption_enforcement(self, rel: str, attr: str, literal: str, exempt: bool) -> None:
        """Drive the ENFORCEMENT directly, not the frozenset contents.

        Review deleted the exemption outright (``if False:``) and every test
        stayed green, because nothing exercised the filter itself. These rows
        fail if the built-in check, its attribute scoping, or the allow-list
        lookup is removed or widened.
        """
        assert _is_exempt(rel, attr, literal) is exempt


class TestNotDetectedShapes:
    """The DOCUMENTED limits, pinned so they cannot be quietly forgotten.

    These are not aspirations. If someone closes one, this test fails and
    they must move it into the DETECTED list — which keeps the docstring's
    claim honest by construction rather than by memory.
    """

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param('T = "pack_tool"\nx = call.name == T\n', id="module-constant-indirection"),
            pytest.param(
                'def f(call):\n    T = "pack_tool"\n    return call.name == T\n',
                id="function-local-constant",
            ),
            pytest.param('x = getattr(call, "name") == "pack_tool"\n', id="getattr"),
            pytest.param('n = call.name\nx = n == "pack_tool"\n', id="intermediate-variable"),
            pytest.param('x = call.name.lower() == "pack_tool"\n', id="normalised"),
            pytest.param(
                'match call.name:\n    case "pack_tool" as chosen:\n        pass\n',
                id="match-as-capture",
            ),
            pytest.param('x = (n := call.name) == "pack_tool"\n', id="walrus"),
            pytest.param(
                'match (call.name, kind):\n    case ("pack_tool", _):\n        pass\n',
                id="tuple-subject-match",
            ),
            pytest.param(
                'import operator\nx = operator.eq(call.name, "pack_tool")\n', id="operator-eq"
            ),
            pytest.param(
                "import operator\nx = operator.contains(NAMES, call.name)\n",
                id="operator-contains",
            ),
            pytest.param("x = call.name == self.TARGET\n", id="attribute-constant"),
            pytest.param(
                "from mod import TARGET\nx = call.name == TARGET\n", id="imported-constant"
            ),
            pytest.param('x = call.name == "pack" + "_tool"\n', id="runtime-concatenation"),
            pytest.param('x = call.name.casefold() == "pack_tool"\n', id="casefold"),
        ],
    )
    def test_known_limit_stays_uncaught(self, source: str) -> None:
        assert _identifier_branches(ast.parse(source)) == []

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param("x = call.name in _BUILTIN_NAMES\n", id="membership-in-named-set"),
            pytest.param('x = other.attr == "value"\n', id="non-identifier-attribute"),
            pytest.param("x = call.name == OTHER\n", id="bare-name-comparand"),
        ],
    )
    def test_sanctioned_forms_never_fire(self, source: str) -> None:
        """These must yield NOTHING.

        The previous version of this test asserted
        ``branches == [] or branches[0][1] == "name"``, which cannot fail for
        any well-formed walker output — a tautology masquerading as a pin.
        Review demonstrated it by making named-set membership fire and
        watching the row stay green.
        """
        assert _identifier_branches(ast.parse(source)) == []

    def test_reviewer_not_walker_decides_legitimacy(self) -> None:
        """``dialect.name`` DOES fire; the allow-list is what licenses it.

        Asserted as a POSITIVE so it goes red if detection is deleted — the
        old row claimed this and could not fail when the walker was gutted.
        """
        branches = _identifier_branches(ast.parse('x = dialect.name == "postgresql"\n'))
        assert branches == [(1, "name", "postgresql")]
        assert not _is_exempt("src/cognic_agentos/db/types.py", "name", "postgresql")
        assert _is_exempt("src/cognic_agentos/db/types.py", "name", "oracle")


def test_allow_list_entries_are_all_still_live() -> None:
    """A stale allow-list entry is a licence nobody is using — remove it."""
    live: set[tuple[str, str, str]] = set()
    for path in _kernel_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(_REPO_ROOT).as_posix()
        for _lineno, attr, literal in _identifier_branches(tree):
            live.add((rel, attr, literal))
    stale = _ALLOWED - live
    assert not stale, f"remove these stale _ALLOWED entries: {sorted(stale)}"
