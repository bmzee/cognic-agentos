"""PR-2a §3.4 — AST drift detector: every self._http.get/post in mcp_authz.py is
preceded (within its function) by a _refuse_non_public_discovery_url guard, or is
routed through a NAMED syntactic exemption. Comments are invisible to ast and are
NOT a valid marker."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TypeGuard

from cognic_agentos.protocol import mcp_authz

# Named exemption registry: functions allowed to issue a deliberately-public
# _http fetch. Empty today — all five legs are guarded. To exempt a future
# public fetch, add its function name here (a real, AST-visible construct).
_GUARD_EXEMPT_FUNCTIONS: frozenset[str] = frozenset()


def _is_guard_call(node: ast.AST) -> TypeGuard[ast.Call]:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_refuse_non_public_discovery_url"
    )


def _is_http_fetch(node: ast.AST) -> TypeGuard[ast.Call]:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "post"}
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "_http"
    )


def _url_arg_dump(call: ast.Call) -> str | None:
    """ast.dump of a call's first positional arg (the URL expression), or None."""
    return ast.dump(call.args[0]) if call.args else None


def _guard_has_leg(call: ast.Call) -> bool:
    return any(kw.arg == "leg" for kw in call.keywords)


def _find_unguarded_fetches(
    source: str, *, exempt: frozenset[str] = _GUARD_EXEMPT_FUNCTIONS
) -> list[tuple[str, int]]:
    """A fetch is guarded IFF a guard earlier in the same function guards the SAME
    url expression (matched by ast.dump of the first positional arg) AND carries a
    `leg=` kwarg. A guard on a DIFFERENT url (e.g. `as_metadata_url`) does NOT
    cover a later `token_endpoint` POST — that URL pairing is the whole point of
    the pin (a coarse "any guard earlier" check would falsely pass a missing
    token-endpoint guard)."""
    tree = ast.parse(source)
    violations: list[tuple[str, int]] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        if fn.name in exempt:
            continue
        guards = [
            (n.lineno, _url_arg_dump(n))
            for n in ast.walk(fn)
            if _is_guard_call(n) and _guard_has_leg(n)
        ]
        for node in ast.walk(fn):
            if not _is_http_fetch(node):
                continue
            fetch_url = _url_arg_dump(node)
            if fetch_url is None or not any(
                g_line < node.lineno and g_url == fetch_url for g_line, g_url in guards
            ):
                violations.append((fn.name, node.lineno))
    return violations


def test_real_mcp_authz_has_no_unguarded_fetches() -> None:
    src = Path(mcp_authz.__file__).read_text()
    assert _find_unguarded_fetches(src) == []


def test_detector_flags_unguarded_fetch() -> None:
    bad = "class C:\n    async def f(self):\n        return await self._http.get('http://x')\n"
    assert _find_unguarded_fetches(bad) == [("f", 3)]


def test_detector_passes_url_matched_guarded_fetch() -> None:
    good = (
        "class C:\n"
        "    async def f(self):\n"
        "        await self._refuse_non_public_discovery_url('http://x', leg='server_url')\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(good) == []


def test_detector_flags_mismatched_guard_for_token_post() -> None:
    """The core regression Codex flagged: an `as_metadata_url` guard must NOT make a
    later `token_endpoint` POST look guarded — the POST has no matching-url guard."""
    src = (
        "class C:\n"
        "    async def _request_token(self):\n"
        "        as_metadata_url = 'http://a'\n"
        "        await self._refuse_non_public_discovery_url(as_metadata_url, leg='as_metadata')\n"
        "        await self._http.get(as_metadata_url)\n"
        "        token_endpoint = 'http://t'\n"
        "        await self._http.post(token_endpoint, data={})\n"
    )
    violations = _find_unguarded_fetches(src)
    assert ("_request_token", 7) in violations  # the token POST is unguarded
    assert ("_request_token", 5) not in violations  # the as_metadata GET IS guarded


def test_detector_flags_guard_without_leg() -> None:
    """A guard missing its `leg=` kwarg does not count — every guard must be leg-tagged."""
    bad = (
        "class C:\n"
        "    async def f(self):\n"
        "        await self._refuse_non_public_discovery_url('http://x')\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(bad) == [("f", 4)]


def test_detector_skips_named_exempt_function() -> None:
    """The exemption is a NAMED function in the registry (a real syntactic marker),
    not a comment. An exempted function's fetch is not flagged."""
    bad = (
        "class C:\n"
        "    async def _unguarded_public_fetch(self):\n"
        "        return await self._http.get('http://x')\n"
    )
    assert _find_unguarded_fetches(bad) == [("_unguarded_public_fetch", 3)]
    assert _find_unguarded_fetches(bad, exempt=frozenset({"_unguarded_public_fetch"})) == []
