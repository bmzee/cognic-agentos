"""Sprint 6 architecture test — caller-controlled URL ban in A2A.

Per the Sprint-6 plan-of-record §"Doctrine Decision B" + the
caller-controlled URL threat model: outbound A2A dispatch URLs MUST
come from a JWS-verified Agent Card's ``supportedInterfaces[].url``
or from operator-controlled :class:`Settings` fields. They MUST NOT
come from caller input (function parameters, request-body fields)
or from model output (LLM-generated strings).

This test is the **static-AST** half of the threat model. The runtime
half is ``tests/unit/protocol/test_a2a_no_caller_controlled_url.py``
(Sprint-6 T14 canary). Both must hold for the threat model to be
intact — even if a future maintainer evades the static check, the
runtime canary trips on the resulting refusal vector.

For background, see ``docs/A2A-CALLER-URL-THREAT-MODEL.md`` (the
authoritative threat-model document; landed alongside this test in
Sprint-6 T4 per the plan-of-record's §"Doctrine Decision B" — see
File Structure line 81 + Doctrine Decision B section).

The collector walks every module under
``src/cognic_agentos/protocol/a2a_*.py`` (recursive — same shape as
:func:`_a2a_modules` in ``test_a2a_no_subprocess.py``) and asserts
that every ``httpx.AsyncClient.{get,post,put,patch,delete,request,send}``
call satisfies one of the **allowed URL sources**:

  1. URL is a string literal (``ast.Constant`` of type ``str``).
  2. URL is a ``Settings.a2a_*_url`` attribute access (operator-
     controlled config field) AND the chain root is NOT a function
     parameter.
  3. URL is a hardcoded well-known suffix concatenated to a verified
     origin via f-string OR ``str.join`` / ``+``, where the variable
     part traces to a non-caller-controlled source (heuristic — the
     runtime canary is the load-bearing half).
  4. URL is an attribute access rooted at one of the verifier-output
     names (``verified_card`` / ``verified_agent_card`` — the tight
     allow-list of names that signal "I came out of
     ``TrustGate.verify_jws_blob``") AND whose chain includes
     ``supported_interfaces`` or ends with ``.url``. **Generic
     ``card`` / ``agent_card`` chain roots are NOT in the allow-list
     and fall through to "unknown" per T4 R2 P2 reviewer correction**
     — implementations MUST rebind verifier output through
     ``verified_card`` / ``verified_agent_card`` before constructing
     dispatch URLs.

**Forbidden URL sources** (the ban list — any one of these in a
``url=...`` argument to ``httpx.AsyncClient.{get,post,put,patch,delete,request,send}``
trips the test):

  - URL is a function parameter of the call site (caller-supplied URL
    flowing in through the function signature).
  - URL is an attribute chain whose **root** is a function parameter
    (T4 R2 P2 — even card-shaped chains like
    ``target_card.supported_interfaces[0].url`` where ``target_card``
    is a function parameter are refused; the chain root is by
    definition caller-controlled).
  - URL is an attribute chain whose root is on the inbound-request
    set (``request`` / ``message`` / ``payload`` / ``envelope`` /
    ``body`` / ``task``) — caller-controlled inbound A2A request.
    Inbound-root refusal happens BEFORE the AgentCard allow-list so
    chains like ``request.supported_interfaces[0].url`` (which look
    card-shaped) are correctly refused.
  - URL is a concatenation that includes any of the above.

URL extraction is method-aware (T4 R1 P2 #1):
  - ``get`` / ``post`` / ``put`` / ``patch`` / ``delete`` — URL at
    positional arg 0 OR keyword ``url=``.
  - ``request`` — URL at positional arg **1** (after method name)
    OR keyword ``url=``. Without method-awareness,
    ``client.request("POST", target_url)`` would have classified the
    literal ``"POST"`` as the URL and the actual caller-supplied
    URL would have slipped past.
  - ``send`` — first positional arg is a Request object, not a URL.
    Static AST cannot trace into Request construction; flagged as
    "no statically-identifiable URL argument" and the runtime canary
    (T14) takes over.

T4 (this commit) ships ZERO ``protocol/a2a_*`` modules; both the main
contract test AND the URL-source classifier are exercised by self-
tests on synthetic AST fragments (the only way to validate the
classifier before any A2A module exists). When T5/T6/T7/T8/T9/T10/T11
land each module, the parametrized arm grows automatically.

Three self-tests pin the collector + the URL-source classifier:
  - ``test_collector_finds_top_level_a2a_files``
  - ``test_url_source_classifier_rejects_caller_param``
  - ``test_url_source_classifier_accepts_agent_card_attr_access``
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

#: Repo source root — three levels up from this file
_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "cognic_agentos" / "protocol"

#: Methods on ``httpx.AsyncClient`` (and ``httpx.Client`` for sync
#: variants) that send an outbound HTTP request. Calls to any of
#: these MUST have a non-caller-controlled URL.
_HTTPX_OUTBOUND_METHODS = frozenset({"get", "post", "put", "patch", "delete", "request", "send"})

#: Identifier roots that signal the ban-list "caller-controlled
#: inbound A2A request". A URL traced to any of these as the chain
#: root is forbidden.
_INBOUND_REQUEST_ROOTS = frozenset({"request", "message", "payload", "envelope", "body", "task"})

#: Identifier name fragments that mark a value as untrusted when used
#: directly as a URL. Used to recognise caller-controlled patterns
#: like ``target_url=...`` / ``webhook_url=...`` flowing through the
#: function signature.
_UNTRUSTED_URL_NAME_FRAGMENTS = frozenset(
    {"target_url", "caller_url", "webhook_url", "remote_url", "callback_url"}
)

#: Tight allow-list of identifier names that signal "this is the
#: output of the JWS verifier" (i.e., a card object that has cleared
#: ``TrustGate.verify_jws_blob`` against the per-tenant trust root).
#:
#: T4 R2 P2 reviewer correction: the previous ``card`` / ``agent_card``
#: heuristic was too permissive — a function parameter named
#: ``target_card`` would have its ``target_card.supported_interfaces[0].url``
#: chain accepted because the root looked card-shaped, even though
#: ``target_card`` was caller-supplied. Tightening to a fixed allow-
#: list of verifier-output names means callers must rebind through a
#: name that explicitly signals "I came out of the verifier" before
#: a chain rooted on this name is accepted. Generic ``card`` /
#: ``agent_card`` chains are now classified as "unknown" rather than
#: "allowed" — the runtime canary (T14) is the load-bearing half for
#: those shapes; reviewers explicitly bless or refuse on a per-call
#: basis.
_VERIFIED_CARD_ROOT_NAMES = frozenset({"verified_card", "verified_agent_card"})

#: Method-receiver names that conventionally name the bound instance
#: (``self``) or class (``cls``) — by Python convention, not caller-
#: supplied data. The function-param-root refusal in step 3b excludes
#: these so that ``self.settings.a2a_outbound_url`` (a normal class-
#: method pattern) doesn't get falsely classified as caller-controlled
#: just because ``self`` appears in the method signature. The
#: settings-shape and verifier-output-rooted allow paths can still
#: fire on chains anchored at ``self`` / ``cls``.
_METHOD_RECEIVER_NAMES = frozenset({"self", "cls"})


def _a2a_modules(src_root: Path | None = None) -> list[Path]:
    """Same collector shape as :func:`_a2a_modules` in
    ``test_a2a_no_subprocess.py``. Re-implemented here (not imported)
    so the two architecture tests stay independent — a future
    refactor of one collector cannot accidentally break the other.

    Collects:

    1. Any path matching ``a2a_*.py`` (top-level + recursive submodule).
    2. Any ``*.py`` inside a directory whose basename starts with
       ``a2a_``.
    3. Excludes only the root ``protocol/__init__.py`` (loader API;
       not A2A surface).
    """
    root = src_root if src_root is not None else _SRC_ROOT
    candidates: set[Path] = set()
    candidates.update(root.rglob("a2a_*.py"))
    for path in root.rglob("*.py"):
        for part in path.parts:
            if part.startswith("a2a_"):
                candidates.add(path)
                break
    candidates.discard(root / "__init__.py")
    return sorted(candidates)


def _attr_chain_root(node: ast.AST) -> str | None:
    """Walk an attribute chain to its leftmost ``ast.Name``, return
    that name's id. Returns None if the chain doesn't bottom out in
    a Name (e.g., ``foo()[0].url``).
    """
    cur = node
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    if isinstance(cur, ast.Name):
        return cur.id
    return None


def _attr_chain_parts(node: ast.AST) -> list[str] | None:
    """Resolve an attribute chain to its dotted parts.

    Returns e.g. ``["card", "supported_interfaces", "url"]`` for
    ``card.supported_interfaces[0].url`` (subscripts collapse to the
    parent attribute). Returns None if the chain doesn't bottom out
    in a Name.
    """
    parts: list[str] = []
    cur: ast.AST = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Subscript):
            # Skip subscripts; treat ``card.supported_interfaces[0].url``
            # the same as ``card.supported_interfaces.url`` for this
            # heuristic.
            cur = cur.value
        else:
            break
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return list(reversed(parts))
    return None


def _classify_url_source(
    url_expr: ast.AST,
    function_param_names: frozenset[str],
) -> tuple[str, str]:
    """Classify a URL expression into ``(verdict, reason)``.

    ``verdict`` is one of:

    - ``"allowed"`` — URL came from a literal, a Settings field, an
      AgentCard attribute access, or a hardcoded well-known suffix.
    - ``"forbidden"`` — URL came from a caller-supplied function
      parameter, an inbound-request attribute chain, or a forbidden
      concatenation.
    - ``"unknown"`` — the classifier couldn't determine the source
      (treated as forbidden; if a future legitimate pattern lands,
      the classifier needs to learn about it).

    ``reason`` is a human-readable explanation for the verdict.
    """
    # 1. String literal — allowed.
    if isinstance(url_expr, ast.Constant) and isinstance(url_expr.value, str):
        return ("allowed", "string literal")

    # 2. Bare ``ast.Name`` — check if it's a function parameter (forbidden)
    #    or an untrusted-name fragment (forbidden).
    if isinstance(url_expr, ast.Name):
        name = url_expr.id
        if name in function_param_names:
            return (
                "forbidden",
                f"caller-supplied function parameter: {name!r}",
            )
        for frag in _UNTRUSTED_URL_NAME_FRAGMENTS:
            if frag in name:
                return (
                    "forbidden",
                    f"untrusted-name fragment in identifier: {name!r}",
                )
        # Bare name that isn't a function parameter and doesn't match
        # an untrusted fragment — treat as unknown (the classifier
        # can't see the binding's source). Conservative: flag as
        # unknown so reviewers explicitly bless or refuse.
        return ("unknown", f"bare name {name!r} — source not classifiable statically")

    # 3. Attribute chain — analyse the root.
    if isinstance(url_expr, ast.Attribute):
        parts = _attr_chain_parts(url_expr)
        if parts is None:
            return ("unknown", "attribute chain root is not a Name")
        root = parts[0]
        leaf = parts[-1]
        # 3a. **Inbound-request attribute chain — forbidden FIRST**
        #     (T4 R1 P2 #2 reviewer correction — must refuse ahead of
        #     the allow-list heuristics below). A chain like
        #     ``request.supported_interfaces[0].url`` LOOKS like a
        #     verified-AgentCard chain because of the
        #     ``supported_interfaces`` segment, but the chain root is
        #     ``request`` — caller-controlled inbound A2A request
        #     data. Same hazard for ``message.agent_card.url`` /
        #     ``payload.agent_card.url``: the ``card``-rooted heuristic
        #     would have wrongly accepted it. Refusing on inbound
        #     roots first means no card-shaped chain rooted at a
        #     caller-controlled object can slip through.
        if root in _INBOUND_REQUEST_ROOTS:
            return (
                "forbidden",
                f"caller-controlled inbound chain: {'.'.join(parts)} (root {root!r})",
            )
        # 3b. **Function-parameter-rooted chain — forbidden** (T4 R2
        #     P2 reviewer correction). A chain whose root is a
        #     function parameter is by definition caller-controlled
        #     regardless of what comes after the root. The previous
        #     classifier let ``target_card.supported_interfaces[0].url``
        #     through because ``supported_interfaces`` matched the
        #     allow-list heuristic — but ``target_card`` was a
        #     function parameter, so the entire chain was caller-
        #     supplied. Refusing function-param roots before the
        #     allow-list closes the false-negative path the reviewer
        #     identified. Mirrors the bare-name function-param check
        #     in step 2 above.
        #
        #     **Exception:** ``self`` and ``cls`` are method receivers
        #     by Python convention, not caller-supplied data. Chains
        #     anchored at ``self`` or ``cls`` (e.g.,
        #     ``self.settings.a2a_outbound_url``) fall through to the
        #     allow-list heuristics below — the receiver was bound at
        #     instance construction or method dispatch, not by the
        #     A2A caller.
        if root in function_param_names and root not in _METHOD_RECEIVER_NAMES:
            return (
                "forbidden",
                f"caller-supplied function parameter as chain root: "
                f"{'.'.join(parts)} (root {root!r})",
            )
        # 3c. ``Settings.a2a_*_url`` — operator-controlled, allowed.
        #     We don't try to pin "Settings" exactly — any chain
        #     ending in ``a2a_*_url`` on a settings-shaped root is
        #     accepted (settings, self.settings, app.state.settings,
        #     etc.). Safe because steps 3a + 3b already refused all
        #     inbound-rooted + function-param-rooted chains, and
        #     ``a2a_*_url`` leaves the leaf-shape to operator-curated
        #     config.
        if leaf.startswith("a2a_") and leaf.endswith("_url"):
            return ("allowed", f"settings field access: {'.'.join(parts)}")
        # 3d. **Tightened verified-AgentCard allow path** (T4 R2 P2
        #     reviewer correction). Only chains rooted at one of the
        #     verifier-output names (``verified_card`` /
        #     ``verified_agent_card``) are accepted. Generic ``card``
        #     / ``agent_card`` roots are no longer in the allow list —
        #     they fall through to "unknown" because the static AST
        #     cannot distinguish a verifier-output ``card`` from a
        #     caller-supplied ``card`` (e.g.,
        #     ``card = request.body.agent_card``). The runtime canary
        #     (T14) carries the load for generic-named card chains.
        #     Implementations MUST rebind the verifier's return value
        #     through ``verified_card`` / ``verified_agent_card``
        #     before constructing dispatch URLs from it.
        if root in _VERIFIED_CARD_ROOT_NAMES and ("supported_interfaces" in parts or leaf == "url"):
            return (
                "allowed",
                f"verified AgentCard attribute access: {'.'.join(parts)}",
            )
        # 3e. Otherwise — unknown.
        return ("unknown", f"attribute chain {'.'.join(parts)} — source not classifiable")

    # 4. f-string (JoinedStr) — analyse each formatted value.
    if isinstance(url_expr, ast.JoinedStr):
        return _classify_fstring(url_expr, function_param_names)

    # 5. Concatenation (BinOp with +) — analyse both sides.
    if isinstance(url_expr, ast.BinOp) and isinstance(url_expr.op, ast.Add):
        left = _classify_url_source(url_expr.left, function_param_names)
        right = _classify_url_source(url_expr.right, function_param_names)
        # If either side is forbidden, the whole concatenation is
        # forbidden. If either is unknown, the whole is unknown.
        if left[0] == "forbidden":
            return ("forbidden", f"concatenation includes forbidden source: {left[1]}")
        if right[0] == "forbidden":
            return ("forbidden", f"concatenation includes forbidden source: {right[1]}")
        if left[0] == "unknown" or right[0] == "unknown":
            return (
                "unknown",
                f"concatenation includes unclassified source ({left[1]}; {right[1]})",
            )
        return ("allowed", f"concatenation of allowed sources ({left[1]}; {right[1]})")

    # 6. Function call — e.g., ``urljoin(...)``, ``str.format(...)``.
    #    Any function call producing a URL is treated as unknown
    #    unless the function is a known-safe constructor. The
    #    runtime canary is the load-bearing half here.
    if isinstance(url_expr, ast.Call):
        return ("unknown", "function call producing URL — defer to runtime canary")

    # 7. Anything else — unknown.
    return ("unknown", f"unrecognised expression type: {type(url_expr).__name__}")


def _classify_fstring(
    node: ast.JoinedStr,
    function_param_names: frozenset[str],
) -> tuple[str, str]:
    """Classify each ``FormattedValue`` inside an f-string. If ANY
    interpolated value is forbidden, the whole f-string is forbidden.
    Constant prefixes/suffixes (the well-known suffix pattern) are
    allowed; the interpolated value's classification is what matters.
    """
    forbidden_reasons: list[str] = []
    unknown_reasons: list[str] = []
    has_well_known_suffix = False
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            # Detect the well-known suffix pattern explicitly.
            if "/.well-known/agent-card.json" in value.value:
                has_well_known_suffix = True
            continue
        if isinstance(value, ast.FormattedValue):
            verdict, reason = _classify_url_source(value.value, function_param_names)
            if verdict == "forbidden":
                forbidden_reasons.append(reason)
            elif verdict == "unknown":
                unknown_reasons.append(reason)
    if forbidden_reasons:
        return ("forbidden", "; ".join(f"f-string interpolates {r}" for r in forbidden_reasons))
    if unknown_reasons:
        joined = "; ".join(f"f-string interpolates {r}" for r in unknown_reasons)
        if has_well_known_suffix:
            # The well-known suffix is a strong signal that this is
            # the agent-card discovery pattern. The runtime canary
            # asserts the suffix is constant and the origin traces
            # to a verified source. For the static check, treat as
            # allowed.
            return ("allowed", f"well-known agent-card discovery pattern ({joined})")
        return ("unknown", joined)
    return ("allowed", "f-string with only constant parts")


def _function_param_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    """Collect every parameter name on a function/async-function def
    (positional, keyword-only, var-positional, var-keyword).
    """
    args = func_node.args
    names: set[str] = set()
    for arg in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs):
        names.add(arg.arg)
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return frozenset(names)


def _enclosing_function_params(tree: ast.AST, target: ast.Call) -> frozenset[str]:
    """Find the smallest function definition enclosing ``target`` and
    return its parameter names. Returns an empty frozenset if the
    call is at module scope."""
    # Walk the tree, tracking each function def's body. The smallest
    # enclosing function is the deepest one whose body contains the
    # target.
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for descendant in ast.walk(node):
                if descendant is target:
                    # Track the deepest match.
                    enclosing = node
                    break
    if enclosing is None:
        return frozenset()
    return _function_param_names(enclosing)


#: Identifier name fragments that signal "this binding is an httpx
#: client". The receiver-name heuristic in :func:`_is_httpx_call` keys
#: off these — a method-call receiver named ``client`` /
#: ``http_client`` / ``_http`` / ``httpx_client`` matches; an unrelated
#: name like ``_tasks`` / ``headers`` / ``mapping`` / ``store`` does
#: not. Reviewers reading T9/T11 task-lifecycle code will see normal
#: ``self._tasks.get(task_id)`` and ``headers.get(name)`` patterns —
#: those MUST NOT be classified as httpx outbound calls (per T4 R3 P2
#: reviewer correction). Sole exception: the literal ``httpx`` module
#: receiver, recognised separately below.
_HTTPX_RECEIVER_NAME_FRAGMENTS = frozenset({"client", "http", "httpx"})


def _collect_httpx_import_aliases(
    tree: ast.AST,
) -> tuple[frozenset[str], frozenset[str]]:
    """Return ``(httpx_module_aliases, constructor_aliases)``.

    T4 R5 P2 reviewer correction: without import-alias tracking, two
    common forms escape :func:`_is_httpx_constructor_call`:

    - ``import httpx as hx`` then ``transport = hx.AsyncClient()`` —
      the constructor's chain root is ``hx``, not ``httpx``.
    - ``from httpx import AsyncClient`` then
      ``transport = AsyncClient()`` — the constructor is a bare Name,
      not an Attribute.

    Both forms must be recognised so the binding tracker correctly
    catches ``transport = ...; await transport.get(target_url)`` no
    matter how the import is spelled.

    Returns:

    - ``httpx_module_aliases`` — set of names that refer to the
      ``httpx`` module in this tree. Always contains ``"httpx"``
      (the literal module name) plus any alias added via
      ``import httpx as <alias>``.
    - ``constructor_aliases`` — set of bare names that refer to the
      ``httpx.AsyncClient`` or ``httpx.Client`` constructors in this
      tree (via ``from httpx import {AsyncClient,Client} [as alias]``).

    Renamed constructor imports like
    ``from httpx import AsyncClient as Async`` are tracked so
    ``Async()`` is recognised as an httpx constructor call.
    """
    module_aliases: set[str] = {"httpx"}
    constructor_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "httpx":
                    bind_name = alias.asname or alias.name
                    module_aliases.add(bind_name)
        elif isinstance(node, ast.ImportFrom):
            if node.module != "httpx":
                continue
            for alias in node.names:
                if alias.name in {"AsyncClient", "Client"}:
                    bind_name = alias.asname or alias.name
                    constructor_aliases.add(bind_name)
    return frozenset(module_aliases), frozenset(constructor_aliases)


def _is_httpx_constructor_call(
    node: ast.AST,
    httpx_module_aliases: frozenset[str] = frozenset({"httpx"}),
    constructor_aliases: frozenset[str] = frozenset(),
) -> bool:
    """Return True iff ``node`` is a call expression that constructs
    an ``httpx`` client.

    Recognises (T4 R5 P2 added import-alias tracking; the original
    only matched the canonical ``httpx`` name):

    - ``httpx.AsyncClient(...)`` / ``httpx.Client(...)``.
    - ``hx.AsyncClient(...)`` after ``import httpx as hx`` — chain
      root in ``httpx_module_aliases``.
    - Either of the above qualified through an arbitrarily-deep
      attribute chain rooted at any name in ``httpx_module_aliases``
      (e.g., ``httpx._async_client.AsyncClient(...)`` — rare but
      defensive).
    - ``AsyncClient(...)`` after ``from httpx import AsyncClient`` —
      bare Name in ``constructor_aliases``.
    - ``Async(...)`` after
      ``from httpx import AsyncClient as Async`` — bare Name in
      ``constructor_aliases`` via the alias.

    Used by :func:`_collect_httpx_client_bindings` to identify the
    RHS of bindings that produce an httpx client.
    """
    if not isinstance(node, ast.Call):
        return False
    callee = node.func
    # Bare ``ast.Name`` — ``from httpx import AsyncClient`` shape.
    if isinstance(callee, ast.Name):
        return callee.id in constructor_aliases
    # ``<httpx-alias>.AsyncClient(...)`` — Attribute call with leaf
    # in the constructor name set + chain root in the module-alias
    # set.
    if isinstance(callee, ast.Attribute):
        if callee.attr not in {"AsyncClient", "Client"}:
            return False
        cur: ast.AST = callee
        while isinstance(cur, ast.Attribute):
            cur = cur.value
        return isinstance(cur, ast.Name) and cur.id in httpx_module_aliases
    return False


def _record_httpx_target(
    target: ast.AST,
    value: ast.AST,
    bound: set[str],
    httpx_module_aliases: frozenset[str],
    constructor_aliases: frozenset[str],
) -> None:
    """Record a binding into ``bound`` if ``value`` is an httpx
    constructor call. Helper shared by the scope-aware collectors
    below."""
    if not _is_httpx_constructor_call(value, httpx_module_aliases, constructor_aliases):
        return
    if isinstance(target, ast.Name):
        bound.add(target.id)
    elif isinstance(target, ast.Attribute):
        # ``self.X = httpx.AsyncClient()`` — record the attribute
        # leaf so ``self.X.get(url)`` matches via leaf-lookup later.
        bound.add(target.attr)


def _scan_for_bindings(
    nodes: list[ast.stmt],
    httpx_module_aliases: frozenset[str],
    constructor_aliases: frozenset[str],
    *,
    descend_into_functions: bool,
) -> set[str]:
    """Walk ``nodes`` and collect httpx-constructor bindings.

    T4 R5 P3 reviewer correction: scope-aware collection. The
    ``descend_into_functions`` flag controls whether we recurse into
    nested function definitions:

    - ``False`` — used for module-scope and class-scope walks; we
      stop at FunctionDef/AsyncFunctionDef boundaries because those
      bindings live in their own per-function scope and shouldn't
      pollute the surrounding scope.
    - ``True`` — used for per-function walks; we recurse through the
      entire function body, including nested compound statements
      (if/for/with/try) but excluding nested functions and classes
      (those have their own scope).

    Either way, ClassDef bodies are NOT descended into (class-scope
    bindings are handled separately by
    :func:`_collect_class_attribute_bindings` so ``self.X = ...``
    bindings are visible across all methods of the same class but
    NOT bleed into other classes or module scope).

    Returns the set of bound names from this scope only.
    """
    bound: set[str] = set()

    def _walk(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    _record_httpx_target(
                        target, stmt.value, bound, httpx_module_aliases, constructor_aliases
                    )
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                _record_httpx_target(
                    stmt.target, stmt.value, bound, httpx_module_aliases, constructor_aliases
                )
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if item.optional_vars is None:
                        continue
                    if not _is_httpx_constructor_call(
                        item.context_expr, httpx_module_aliases, constructor_aliases
                    ):
                        continue
                    if isinstance(item.optional_vars, ast.Name):
                        bound.add(item.optional_vars.id)
                    elif isinstance(item.optional_vars, ast.Attribute):
                        bound.add(item.optional_vars.attr)
                # Descend into the with-block body (it's still in
                # the same scope as the with-statement itself).
                _walk(stmt.body)
            elif isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                _walk(stmt.body)
                _walk(stmt.orelse)
            elif isinstance(stmt, ast.Try):
                _walk(stmt.body)
                for handler in stmt.handlers:
                    _walk(handler.body)
                _walk(stmt.orelse)
                _walk(stmt.finalbody)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                descend_into_functions
            ):
                _walk(stmt.body)
                # If descend_into_functions is False: stop at the
                # function boundary; per-function bindings are
                # collected separately.
            # ClassDef bodies are NOT walked here — class-attribute
            # bindings are collected by
            # :func:`_collect_class_attribute_bindings`.

    _walk(nodes)
    return bound


def _collect_module_scope_bindings(
    tree: ast.Module,
    httpx_module_aliases: frozenset[str],
    constructor_aliases: frozenset[str],
) -> frozenset[str]:
    """Collect bindings produced by top-level statements of the
    module (NOT inside any FunctionDef/AsyncFunctionDef/ClassDef).
    These are visible to every call in the module."""
    return frozenset(
        _scan_for_bindings(
            list(tree.body),
            httpx_module_aliases,
            constructor_aliases,
            descend_into_functions=False,
        )
    )


def _collect_function_local_bindings(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    httpx_module_aliases: frozenset[str],
    constructor_aliases: frozenset[str],
) -> frozenset[str]:
    """Collect bindings produced inside ``func_node``'s body
    (excluding nested function/class boundaries). Visible only to
    calls within the same function."""
    return frozenset(
        _scan_for_bindings(
            list(func_node.body),
            httpx_module_aliases,
            constructor_aliases,
            descend_into_functions=False,
        )
    )


def _collect_class_attribute_bindings(
    class_node: ast.ClassDef,
    httpx_module_aliases: frozenset[str],
    constructor_aliases: frozenset[str],
) -> frozenset[str]:
    """Collect ``self.X = httpx...`` bindings from any method body
    of ``class_node``. The leaf attribute name (``X``) enters the
    binding set so ``self.X.get(url)`` matches via leaf-lookup from
    any method of the same class.

    Methods in OTHER classes (or at module scope) DO NOT see these
    bindings — class-attribute scope is preserved.
    """
    bound: set[str] = set()
    for stmt in class_node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            method_bindings = _scan_for_bindings(
                list(stmt.body),
                httpx_module_aliases,
                constructor_aliases,
                descend_into_functions=True,
            )
            # Of these, retain ONLY attribute-leaf bindings — bare-
            # name local vars are scoped to the method, not the
            # class. We re-walk the body looking for Attribute
            # targets specifically.
            for inner in ast.walk(stmt):
                if isinstance(inner, ast.Assign):
                    for target in inner.targets:
                        if isinstance(target, ast.Attribute) and _is_httpx_constructor_call(
                            inner.value, httpx_module_aliases, constructor_aliases
                        ):
                            bound.add(target.attr)
                elif (
                    isinstance(inner, ast.AnnAssign)
                    and inner.value is not None
                    and isinstance(inner.target, ast.Attribute)
                    and _is_httpx_constructor_call(
                        inner.value, httpx_module_aliases, constructor_aliases
                    )
                ):
                    bound.add(inner.target.attr)
            # Avoid the unused-binding linter complaint.
            _ = method_bindings
    return frozenset(bound)


def _enclosing_function_def(
    tree: ast.AST,
    target: ast.Call,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Find the deepest FunctionDef/AsyncFunctionDef whose body
    contains ``target``. Returns None if the call is at module scope
    (top-level statement)."""
    enclosing: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for descendant in ast.walk(node):
                if descendant is target:
                    enclosing = node
                    break
    return enclosing


def _enclosing_class_def(
    tree: ast.AST,
    target: ast.Call,
) -> ast.ClassDef | None:
    """Find the deepest ClassDef whose body contains ``target``.
    Returns None if the call is not inside any class."""
    enclosing: ast.ClassDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for descendant in ast.walk(node):
                if descendant is target:
                    enclosing = node
                    break
    return enclosing


def _bindings_visible_at(
    tree: ast.Module,
    target_call: ast.Call,
    httpx_module_aliases: frozenset[str],
    constructor_aliases: frozenset[str],
) -> frozenset[str]:
    """Return the httpx-binding set visible at ``target_call``'s
    location (T4 R5 P3 reviewer correction).

    The set is the union of three scopes:

    - **Module scope** — top-level bindings (always visible).
    - **Function scope** — bindings inside the smallest enclosing
      function/method (visible only to calls within that function).
    - **Class scope** — ``self.X = httpx...`` bindings from any
      method of the smallest enclosing class (visible to all methods
      of the same class).

    Without scope-awareness (the previous module-wide binding set),
    a ``session = httpx.AsyncClient()`` in one function would have
    ``session.<method>(...)`` calls in unrelated functions wrongly
    flagged as httpx — reintroducing the false-positive class R3 P2
    was meant to eliminate.
    """
    bindings: set[str] = set(
        _collect_module_scope_bindings(tree, httpx_module_aliases, constructor_aliases)
    )
    func = _enclosing_function_def(tree, target_call)
    if func is not None:
        bindings.update(
            _collect_function_local_bindings(func, httpx_module_aliases, constructor_aliases)
        )
    cls = _enclosing_class_def(tree, target_call)
    if cls is not None:
        bindings.update(
            _collect_class_attribute_bindings(cls, httpx_module_aliases, constructor_aliases)
        )
    return frozenset(bindings)


def _is_httpx_receiver(
    receiver: ast.AST,
    httpx_bindings: frozenset[str] = frozenset(),
    httpx_module_aliases: frozenset[str] = frozenset({"httpx"}),
    constructor_aliases: frozenset[str] = frozenset(),
) -> bool:
    """Return True iff ``receiver`` looks like an httpx client binding.

    Heuristic (T4 R3 P2 + R4 P2 + R5 P2 + R6 P2 reviewer corrections):
    the architecture test MUST distinguish actual httpx outbound
    calls from same-named methods on unrelated objects
    (``self._tasks.get(task_id)`` / ``headers.get(name)`` /
    ``mapping.get(key)`` / ``store.get(id)``) — that's the R3 P2 fix.
    But it ALSO must catch httpx clients bound to non-conforming
    names (``transport = httpx.AsyncClient(); transport.get(url)``)
    — that's the R4 P2 fix. AND direct alias-constructor receivers
    (``import httpx as hx; hx.AsyncClient().get(url)`` and
    ``from httpx import AsyncClient; AsyncClient().get(url)``) — the
    R6 P2 fix that threads ``httpx_module_aliases`` +
    ``constructor_aliases`` through this check.

    A receiver matches if any of:

    - **Tracked binding** — the receiver's bare-name or
      attribute-leaf name is in ``httpx_bindings`` (a name produced
      by ``transport = httpx.AsyncClient()``,
      ``self.session = httpx.Client()``,
      ``async with httpx.AsyncClient() as session:``, etc.).
    - **Fragment match** — bare ``Name`` or attribute leaf contains
      a fragment in :data:`_HTTPX_RECEIVER_NAME_FRAGMENTS`
      (``client``, ``http``, ``httpx``). Catches the common
      ``client.get(...)``, ``self.http_client.post(...)`` shapes.
    - **httpx-rooted attribute chain** — chain root is the literal
      ``httpx`` module (``httpx.AsyncClient.get(...)``).
    - **Direct alias-constructor receiver** (R6 P2) — the Call
      receiver IS itself an httpx constructor under any alias form
      (``hx.AsyncClient()``, ``AsyncClient()`` after
      ``from httpx import AsyncClient``, ``Async()`` after
      ``from httpx import AsyncClient as Async``). Recognised via
      :func:`_is_httpx_constructor_call` with the alias sets.
    """
    # Receiver = bare ``ast.Name``: e.g. ``client.get(url)`` or
    # ``transport.get(url)`` (R4 P2 — tracked binding).
    if isinstance(receiver, ast.Name):
        if receiver.id in httpx_bindings:
            return True
        return any(frag in receiver.id for frag in _HTTPX_RECEIVER_NAME_FRAGMENTS)
    # Receiver = ``ast.Attribute``: e.g. ``self.client.get(url)``,
    # ``self.transport.get(url)``, ``httpx.AsyncClient.get(url)``.
    if isinstance(receiver, ast.Attribute):
        # R4 P2 — tracked-binding leaf (``self._client.get(...)``
        # where ``_client`` was set to ``httpx.AsyncClient()`` in
        # __init__).
        if receiver.attr in httpx_bindings:
            return True
        if any(frag in receiver.attr for frag in _HTTPX_RECEIVER_NAME_FRAGMENTS):
            return True
        # Chain root signal: ``httpx.<anything>.method(...)``.
        cur: ast.AST = receiver
        while isinstance(cur, ast.Attribute):
            cur = cur.value
        return isinstance(cur, ast.Name) and "httpx" in cur.id
    # Receiver = ``ast.Call``: ``httpx.AsyncClient().get(url)`` /
    # ``hx.AsyncClient().get(url)`` (R5 P2 alias) /
    # ``AsyncClient().get(url)`` (R5 P2 bare-import) — recognise via
    # the alias-aware constructor matcher (R6 P2 reviewer correction:
    # the previous recursion called ``_is_httpx_receiver`` without
    # the alias sets, so direct alias-constructor calls bypassed the
    # check).
    if isinstance(receiver, ast.Call):
        return _is_httpx_constructor_call(receiver, httpx_module_aliases, constructor_aliases)
    return False


def _is_httpx_call(
    call_node: ast.Call,
    httpx_bindings: frozenset[str] = frozenset(),
    httpx_module_aliases: frozenset[str] = frozenset({"httpx"}),
    constructor_aliases: frozenset[str] = frozenset(),
) -> str | None:
    """If ``call_node`` is a call on an ``httpx`` client whose method
    is in :data:`_HTTPX_OUTBOUND_METHODS`, return the method name.
    Otherwise return None.

    Recognised patterns (T4 R3 P2 narrowed; T4 R4 P2 added tracked
    bindings; T4 R5 P2 added import-alias tracking; T4 R6 P2 threaded
    aliases into direct-constructor-receiver detection):

    - ``client.get(url)`` / ``http_client.post(url)`` /
      ``async_client.delete(url)`` — receiver name contains
      ``client`` / ``http`` / ``httpx`` per
      :data:`_HTTPX_RECEIVER_NAME_FRAGMENTS`.
    - ``self.client.get(url)`` / ``self._http.post(url)`` —
      attribute-chain leaf contains a fragment.
    - ``transport.get(url)`` after ``transport = httpx.AsyncClient()``
      — tracked binding (R4 P2).
    - ``self.transport.get(url)`` after
      ``self.transport = httpx.AsyncClient()`` — tracked-binding leaf.
    - ``httpx.AsyncClient().get(url)`` — Call-receiver with literal
      ``httpx`` module.
    - ``hx.AsyncClient().get(url)`` after ``import httpx as hx`` —
      Call-receiver with module alias (R6 P2).
    - ``AsyncClient().get(url)`` after
      ``from httpx import AsyncClient`` — Call-receiver with bare
      constructor (R6 P2).
    - ``Async().get(url)`` after
      ``from httpx import AsyncClient as Async`` — Call-receiver
      with renamed bare constructor (R6 P2).
    - ``httpx.AsyncClient.get(url)`` — chain rooted at the ``httpx``
      module (rare).

    Filtered out (no longer flagged):

    - ``self._tasks.get(task_id)`` — task-store dict-like access.
    - ``headers.get(name)`` — header-dict access.
    - ``mapping.get(key)`` / ``cache.get(key)`` /
      ``registry.get(name)`` — generic dict-like accesses.
    """
    if not isinstance(call_node.func, ast.Attribute):
        return None
    method = call_node.func.attr
    if method not in _HTTPX_OUTBOUND_METHODS:
        return None
    if not _is_httpx_receiver(
        call_node.func.value, httpx_bindings, httpx_module_aliases, constructor_aliases
    ):
        return None
    return method


#: httpx outbound methods whose **first positional argument** is the
#: URL. ``client.get(url, ...)`` / ``client.post(url, ...)`` etc.
_HTTPX_URL_AT_POS_0 = frozenset({"get", "post", "put", "patch", "delete"})

#: httpx outbound methods whose **second positional argument** is the
#: URL. ``client.request(method, url, ...)`` — the method name is
#: positional arg 0; the URL is positional arg 1. (Per
#: :class:`httpx.Client.request` signature.) Without this distinction,
#: a call like ``client.request("POST", target_url)`` would have its
#: literal ``"POST"`` classified as the URL and the actual
#: caller-controlled URL would slip past — this is the T4 R1 P2 #1
#: reviewer-correction case.
_HTTPX_URL_AT_POS_1 = frozenset({"request"})

#: httpx outbound methods whose first positional argument is a
#: :class:`httpx.Request` object (not a URL). ``client.send(request)``
#: — the URL lives on the Request object's ``.url`` attribute. We do
#: NOT trace into the Request construction site statically (that's
#: the runtime canary's job); instead, we treat the call as having
#: an unknown URL source unless a ``url=`` kwarg is also given (which
#: httpx ignores for ``send`` but a defensive maintainer could add
#: as a docstring marker).
_HTTPX_URL_AS_REQUEST_OBJECT = frozenset({"send"})


def _extract_url_arg(
    call_node: ast.Call,
    method: str,
) -> ast.AST | None:
    """Return the URL argument expression for an httpx call, or None
    if the call has no URL argument we can identify (in which case
    the caller treats the call as an "unknown URL source" — the
    runtime canary asserts the missing surface fails closed).

    Method-aware extraction (T4 R1 P2 #1 reviewer correction): the
    positional offset of the URL depends on which httpx method is
    being called.

    - ``get`` / ``post`` / ``put`` / ``patch`` / ``delete`` — URL is
      at positional arg 0 OR keyword ``url=``.
    - ``request`` — URL is at positional arg **1** (after the method
      name) OR keyword ``url=``.
    - ``send`` — first positional arg is a :class:`httpx.Request`
      object, NOT a URL. Static AST cannot trace into the Request
      construction; return None so the caller flags this as
      "unknown URL source" and the runtime canary takes over.
    """
    # Keyword form: client.{method}(url=<expr>, ...) — works for all
    # methods (httpx accepts ``url=`` on every URL-taking method).
    for kw in call_node.keywords:
        if kw.arg == "url":
            return kw.value

    # Method-aware positional extraction.
    if method in _HTTPX_URL_AT_POS_0:
        return call_node.args[0] if call_node.args else None
    if method in _HTTPX_URL_AT_POS_1:
        # client.request(method, url, ...) — URL is positional arg 1.
        return call_node.args[1] if len(call_node.args) >= 2 else None
    if method in _HTTPX_URL_AS_REQUEST_OBJECT:
        # client.send(request) — URL is on the Request object;
        # static AST cannot trace it. Caller treats as unknown.
        return None
    # Method recognised by ``_is_httpx_call`` but not handled above.
    # Defensive: treat as unknown so the caller flags it (rather than
    # silently returning args[0] and possibly miscategorising).
    return None


def _check_caller_controlled_urls(tree: ast.Module, path: Path) -> list[str]:
    """Find every httpx outbound call in the tree and classify its
    URL source. Returns a list of violation strings (one per
    forbidden / unknown call).

    T4 R4 P2 + R5 P2 + R5 P3 reviewer corrections:

    - **Import-alias tracking** (R5 P2) — module-level pre-pass
      collects ``import httpx as <alias>`` and
      ``from httpx import {AsyncClient,Client} [as <alias>]`` bindings
      so renamed imports + bare-constructor patterns are recognised
      as httpx constructors.
    - **Scope-aware binding lookup** (R5 P3) — instead of one
      module-wide binding set, each call site gets the union of
      module-scope bindings + the smallest enclosing function's
      bindings + the smallest enclosing class's instance-attribute
      bindings. A ``session = httpx.AsyncClient()`` in one function
      no longer leaks into ``session.get(...)`` calls in other
      functions of the same module.
    """
    httpx_module_aliases, constructor_aliases = _collect_httpx_import_aliases(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Per-call scope-aware binding set (R5 P3).
        bindings_here = _bindings_visible_at(tree, node, httpx_module_aliases, constructor_aliases)
        method = _is_httpx_call(node, bindings_here, httpx_module_aliases, constructor_aliases)
        if method is None:
            continue
        url_expr = _extract_url_arg(node, method)
        if url_expr is None:
            # No URL arg we can identify — treat as unknown. For
            # ``send(request)`` calls this is expected (URL lives on
            # the Request object) and the runtime canary takes over.
            violations.append(
                f"{path.name}:{node.lineno} — httpx.{method}() call with "
                f"no statically-identifiable URL argument"
            )
            continue
        param_names = _enclosing_function_params(tree, node)
        verdict, reason = _classify_url_source(url_expr, param_names)
        if verdict == "forbidden":
            violations.append(
                f"{path.name}:{node.lineno} — httpx.{method}(url=...) "
                f"with forbidden source: {reason}"
            )
        elif verdict == "unknown":
            violations.append(
                f"{path.name}:{node.lineno} — httpx.{method}(url=...) "
                f"with unclassified source: {reason}"
            )
    return violations


class TestA2aNoCallerControlledUrl:
    """The architectural guardrail. Every httpx outbound call in any
    ``protocol/a2a_*`` module MUST have a URL traced to a literal,
    a Settings field, a verified AgentCard attribute, or a well-known
    suffix pattern.

    If this test fails, REVERT the offending edit. The threat model
    in ``docs/A2A-CALLER-URL-THREAT-MODEL.md`` documents the four
    reachable URL surfaces and why caller-controlled URLs are
    unacceptable in the A2A dispatch path.
    """

    @pytest.mark.parametrize(
        "module_path",
        _a2a_modules() or [pytest.param(None, id="no-a2a-modules-yet")],
    )
    def test_no_caller_controlled_urls(self, module_path: Path | None) -> None:
        """Every A2A module must clear the URL-source classifier.
        Parametrized arm grows from ``[None]`` (T4 — this commit) as
        T5/T6/T7/T8/T9/T10/T11 land each module.
        """
        if module_path is None:
            pytest.skip(
                "no a2a_* modules exist yet under protocol/; "
                "this arm collects automatically as T5-T11 land each module"
            )
        source = module_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(module_path))
        violations = _check_caller_controlled_urls(tree, module_path)
        assert not violations, (
            f"Sprint-6 A2A caller-URL architecture test failed for "
            f"{module_path.name}:\n"
            + "\n".join(f"  - {v}" for v in violations)
            + "\n\nPer Sprint-6 plan §Doctrine Decision B + "
            "docs/A2A-CALLER-URL-THREAT-MODEL.md: outbound A2A dispatch "
            "URLs MUST come from a JWS-verified Agent Card rebound "
            "through ``verified_card`` / ``verified_agent_card`` "
            "(verifier-output allow-list) accessed via "
            "supported_interfaces[*].url OR .url; OR from a "
            "Settings.a2a_*_url field; OR from a hardcoded well-known "
            "suffix. Caller input (function parameters, function-"
            "parameter-rooted attribute chains, inbound-request "
            "attribute chains rooted at request/message/payload/"
            "envelope/body/task, model output) MUST NOT reach "
            "httpx.AsyncClient.{get,post,put,patch,delete,request,send}. "
            "The runtime canary "
            "tests/unit/protocol/test_a2a_no_caller_controlled_url.py "
            "(T14) is the runtime complement to this static check."
        )


class TestModuleCollectorSelfTests:
    """Self-tests for :func:`_a2a_modules`. Mirrors
    ``test_a2a_no_subprocess.py``'s collector self-tests so a
    regression in either module surfaces here too."""

    def test_collector_finds_top_level_a2a_files(self, tmp_path: Path) -> None:
        """Top-level ``protocol/a2a_*.py`` files MUST be picked up."""
        fake_root = tmp_path / "protocol"
        fake_root.mkdir()
        (fake_root / "a2a_endpoint.py").write_text("# stub", encoding="utf-8")
        (fake_root / "a2a_authz.py").write_text("# stub", encoding="utf-8")
        # The root protocol/__init__.py MUST be excluded
        (fake_root / "__init__.py").write_text("", encoding="utf-8")
        # An MCP file — also must NOT be collected
        (fake_root / "mcp_host.py").write_text("# stub", encoding="utf-8")

        modules = _a2a_modules(src_root=fake_root)
        names = {p.name for p in modules}

        assert {"a2a_endpoint.py", "a2a_authz.py"} <= names
        assert (fake_root / "__init__.py") not in modules
        assert "mcp_host.py" not in names

    def test_collector_finds_nested_a2a_submodules(self, tmp_path: Path) -> None:
        """Nested submodules and the package's ``__init__.py`` MUST
        be in scope."""
        fake_root = tmp_path / "protocol"
        nested = fake_root / "a2a_endpoint"
        nested.mkdir(parents=True)
        (nested / "helpers.py").write_text("# stub", encoding="utf-8")
        (nested / "__init__.py").write_text("", encoding="utf-8")

        modules = _a2a_modules(src_root=fake_root)
        names = {p.name for p in modules}

        assert "helpers.py" in names
        assert (nested / "__init__.py") in modules


class TestUrlSourceClassifier:
    """Contract tests for :func:`_classify_url_source` — the load-
    bearing classifier. Without these, a regression that drops the
    forbidden-pattern check (or accepts an inbound-request chain) could
    silently mask drift in the main contract test above.

    Each test feeds a synthetic ``url=...`` argument expression
    through the classifier and asserts the verdict.
    """

    def _classify(
        self,
        source: str,
        param_names: frozenset[str] = frozenset(),
    ) -> tuple[str, str]:
        """Parse a single Python expression and classify it. The
        expression MUST be the right-hand side of an assignment so
        the AST has a parseable statement; the helper extracts the
        value expression from the AssignNode.
        """
        wrapper = f"_url = {source}\n"
        tree = ast.parse(wrapper)
        assign = tree.body[0]
        assert isinstance(assign, ast.Assign)
        return _classify_url_source(assign.value, param_names)

    def test_classifier_accepts_string_literal(self) -> None:
        """``"https://example.com/path"`` → allowed."""
        verdict, _ = self._classify('"https://example.com/path"')
        assert verdict == "allowed"

    def test_classifier_accepts_settings_field_access(self) -> None:
        """``settings.a2a_outbound_request_url`` → allowed."""
        verdict, reason = self._classify("settings.a2a_outbound_request_url")
        assert verdict == "allowed", f"settings field rejected: {reason}"
        assert "settings" in reason

    def test_classifier_accepts_self_settings_field_access(self) -> None:
        """``self.settings.a2a_endpoint_url`` → allowed (chains with
        a Settings-shaped tail are accepted regardless of root)."""
        verdict, _ = self._classify("self.settings.a2a_endpoint_url")
        assert verdict == "allowed"

    def test_url_source_classifier_accepts_agent_card_attr_access(self) -> None:
        """``verified_card.supported_interfaces[0].url`` → allowed
        (verifier-output AgentCard attribute chain). This is the
        load-bearing positive-classifier contract — the threat model
        permits this exact shape and forbids everything else.

        T4 R2 P2 reviewer correction: the chain root MUST be a
        verifier-output name (``verified_card`` /
        ``verified_agent_card``), NOT a generic ``card``. Generic
        ``card`` roots fall through to "unknown" because the static
        AST cannot tell whether ``card`` is the verifier's return
        value or a function parameter."""
        verdict, reason = self._classify("verified_card.supported_interfaces[0].url")
        assert verdict == "allowed", f"verified AgentCard attr access rejected: {reason}"
        assert "verified" in reason.lower() or "supported_interfaces" in reason

    def test_classifier_accepts_verified_card_url_attr(self) -> None:
        """``verified_card.url`` → allowed (root name is on the
        verifier-output allow-list)."""
        verdict, _ = self._classify("verified_card.url")
        assert verdict == "allowed"

    def test_classifier_accepts_verified_agent_card_attr_access(self) -> None:
        """``verified_agent_card.supported_interfaces[0].url`` → allowed
        (the second name on the verifier-output allow-list)."""
        verdict, _ = self._classify("verified_agent_card.supported_interfaces[0].url")
        assert verdict == "allowed"

    def test_classifier_rejects_generic_card_root_as_unknown(self) -> None:
        """**T4 R2 P2 contract test:** generic ``card.supported_interfaces[0].url``
        — chain root is a non-allow-listed name. Static AST cannot
        determine whether ``card`` came from the verifier or from a
        caller, so the classifier returns "unknown" (the runtime
        canary is the load-bearing half). Implementations MUST rebind
        the verifier's return through ``verified_card`` /
        ``verified_agent_card``."""
        verdict, reason = self._classify("card.supported_interfaces[0].url")
        assert verdict == "unknown", (
            f"Generic ``card`` root accepted; should be unknown so the "
            f"runtime canary takes over: {reason}"
        )

    def test_classifier_rejects_generic_agent_card_root_as_unknown(self) -> None:
        """``agent_card.url`` → unknown (same rationale as above)."""
        verdict, _ = self._classify("agent_card.url")
        assert verdict == "unknown"

    def test_url_source_classifier_rejects_caller_param(self) -> None:
        """``target_url`` (a function parameter) → forbidden. This
        is the load-bearing negative-classifier contract — the
        threat model's primary concern."""
        verdict, reason = self._classify("target_url", param_names=frozenset({"target_url"}))
        assert verdict == "forbidden", f"caller-supplied param accepted: {reason}"
        assert "function parameter" in reason or "target_url" in reason

    def test_classifier_rejects_inbound_request_chain(self) -> None:
        """``request.body.url`` → forbidden (caller-controlled
        inbound A2A request)."""
        verdict, reason = self._classify("request.body.url")
        assert verdict == "forbidden", f"inbound request chain accepted: {reason}"
        assert "inbound" in reason or "request" in reason

    def test_classifier_rejects_message_target_url_chain(self) -> None:
        """``message.target_url`` → forbidden."""
        verdict, _ = self._classify("message.target_url")
        assert verdict == "forbidden"

    def test_classifier_rejects_payload_url_chain(self) -> None:
        """``payload.url`` → forbidden."""
        verdict, _ = self._classify("payload.url")
        assert verdict == "forbidden"

    def test_classifier_rejects_untrusted_name_fragment(self) -> None:
        """A bare ``webhook_url`` identifier (untrusted-name fragment)
        → forbidden. Catches the case where a function shadows
        ``webhook_url`` as a local variable, evading the function-
        parameter check."""
        verdict, reason = self._classify("webhook_url")
        assert verdict == "forbidden", f"untrusted-name fragment accepted: {reason}"
        assert "untrusted" in reason or "webhook_url" in reason

    def test_classifier_rejects_concatenation_with_caller_param(self) -> None:
        """``base + target_url`` → forbidden because target_url is a
        function parameter."""
        verdict, reason = self._classify(
            "base + target_url", param_names=frozenset({"base", "target_url"})
        )
        assert verdict == "forbidden", f"forbidden concat accepted: {reason}"

    def test_classifier_accepts_well_known_suffix_pattern(self) -> None:
        """``f"{origin}/.well-known/agent-card.json"`` → allowed (the
        well-known suffix pattern is recognised; the runtime canary
        is the load-bearing half — it asserts the origin traces to
        a verified source)."""
        verdict, reason = self._classify('f"{origin}/.well-known/agent-card.json"')
        assert verdict == "allowed", f"well-known pattern rejected: {reason}"
        assert "well-known" in reason

    def test_classifier_rejects_well_known_pattern_with_caller_origin(self) -> None:
        """``f"{request_origin}/.well-known/agent-card.json"`` where
        ``request_origin`` is a function parameter — the f-string
        suffix is well-known but the interpolated value is forbidden,
        so the verdict is forbidden (not allowed). The interpolation-
        side ban beats the well-known-suffix-side acceptance."""
        verdict, reason = self._classify(
            'f"{request_origin}/.well-known/agent-card.json"',
            param_names=frozenset({"request_origin"}),
        )
        assert verdict == "forbidden", (
            f"well-known pattern with forbidden interpolation accepted: {reason}"
        )

    def test_classifier_unknown_for_unclassified_attr_chain(self) -> None:
        """``something.random.attr`` → unknown (treated as a violation;
        the caller must use a recognised pattern)."""
        verdict, _ = self._classify("something.random.attr")
        assert verdict == "unknown"

    def test_classifier_unknown_for_function_call(self) -> None:
        """``urljoin(a, b)`` → unknown (defer to runtime canary)."""
        verdict, reason = self._classify("urljoin(a, b)")
        assert verdict == "unknown"
        assert "function call" in reason or "runtime canary" in reason

    def test_classifier_rejects_inbound_supported_interfaces_chain(self) -> None:
        """**T4 R1 P2 #2 contract test:** ``request.supported_interfaces[0].url``
        — chain LOOKS like a verified-AgentCard chain because of the
        ``supported_interfaces`` segment, but the chain root is
        ``request`` (caller-controlled inbound A2A request). The
        previous classifier accepted this because the
        ``supported_interfaces`` allow-list heuristic ran BEFORE the
        inbound-root refusal. Reordering (refuse inbound roots first)
        closes the false-negative path."""
        verdict, reason = self._classify("request.supported_interfaces[0].url")
        assert verdict == "forbidden", f"Inbound chain with supported_interfaces accepted: {reason}"
        assert "request" in reason

    def test_classifier_rejects_message_agent_card_url_chain(self) -> None:
        """**T4 R1 P2 #2 contract test:** ``message.agent_card.url`` —
        chain LOOKS like a verified-AgentCard ``card.url`` access, but
        the chain root is ``message`` (caller-controlled inbound A2A
        envelope). Same hazard class as the supported_interfaces
        case above."""
        verdict, reason = self._classify("message.agent_card.url")
        assert verdict == "forbidden", f"Inbound chain with agent_card.url accepted: {reason}"
        assert "message" in reason

    def test_classifier_rejects_payload_agent_card_url_chain(self) -> None:
        """**T4 R1 P2 #2 contract test:** ``payload.agent_card.url`` —
        same hazard class; root ``payload`` is caller-controlled."""
        verdict, _ = self._classify("payload.agent_card.url")
        assert verdict == "forbidden"

    def test_classifier_rejects_envelope_supported_interfaces_chain(self) -> None:
        """**T4 R1 P2 #2 contract test:** ``envelope.supported_interfaces[0].url``
        — root ``envelope`` is on the inbound-roots list."""
        verdict, _ = self._classify("envelope.supported_interfaces[0].url")
        assert verdict == "forbidden"

    def test_classifier_still_accepts_verifier_output_chains_after_reorder(self) -> None:
        """Negative control for the R1 P2 #2 reorder + R2 P2 tightening:
        a verifier-output ``verified_card.supported_interfaces[0].url``
        chain is still accepted (root is on the verifier-output
        allow-list, not on the inbound-roots list, and not a function
        parameter). The two fixes together are precise — they don't
        over-broaden the refusal."""
        verdict, reason = self._classify("verified_card.supported_interfaces[0].url")
        assert verdict == "allowed", (
            f"Verifier-output AgentCard chain refused after R1 + R2 reorder: {reason}"
        )

    def test_classifier_still_accepts_verified_card_url_after_reorder(self) -> None:
        """Negative control: ``verified_card.url`` still accepted."""
        verdict, _ = self._classify("verified_card.url")
        assert verdict == "allowed"

    def test_classifier_still_accepts_settings_a2a_url_after_reorder(self) -> None:
        """Negative control: ``settings.a2a_outbound_url`` still
        accepted (root ``settings`` is not on the inbound-roots
        list; leaf matches the ``a2a_*_url`` shape)."""
        verdict, _ = self._classify("settings.a2a_outbound_url")
        assert verdict == "allowed"

    def test_classifier_rejects_function_param_card_root(self) -> None:
        """**T4 R2 P2 contract test:** the canonical false-negative
        the reviewer named. ``target_card.supported_interfaces[0].url``
        where ``target_card`` is a function parameter — chain LOOKS
        verifier-shaped but the root is a function parameter, by
        definition caller-controlled. The previous classifier let
        this through because the ``supported_interfaces`` heuristic
        ran ahead of any function-param-root check; the corrected
        ordering refuses it."""
        verdict, reason = self._classify(
            "target_card.supported_interfaces[0].url",
            param_names=frozenset({"target_card"}),
        )
        assert verdict == "forbidden", f"Function-param-rooted card-shaped chain accepted: {reason}"
        assert "function parameter" in reason
        assert "target_card" in reason

    def test_classifier_rejects_function_param_card_root_with_url_leaf(self) -> None:
        """**T4 R2 P2 contract test:** ``card.url`` where ``card`` is
        a function parameter — same hazard class, simpler chain."""
        verdict, reason = self._classify(
            "card.url",
            param_names=frozenset({"card"}),
        )
        assert verdict == "forbidden", f"Function-param-rooted card.url chain accepted: {reason}"
        assert "function parameter" in reason

    def test_classifier_rejects_function_param_with_a2a_settings_leaf_shape(
        self,
    ) -> None:
        """**T4 R2 P2 contract test:** ``cfg.a2a_outbound_url`` where
        ``cfg`` is a function parameter — chain leaf LOOKS
        settings-shaped (``a2a_*_url``) but the root is a function
        parameter. Function-param-root refusal must run before the
        settings-shape allow path, so this chain is correctly
        forbidden."""
        verdict, reason = self._classify(
            "cfg.a2a_outbound_url",
            param_names=frozenset({"cfg"}),
        )
        assert verdict == "forbidden", (
            f"Function-param-rooted settings-shaped chain accepted: {reason}"
        )
        assert "function parameter" in reason

    def test_classifier_accepts_settings_chain_when_settings_is_not_param(
        self,
    ) -> None:
        """Negative control for the function-param refusal: a chain
        rooted at ``settings`` that is NOT a function parameter (a
        module-level binding or a closure variable) still passes the
        settings-shape allow path."""
        verdict, _ = self._classify(
            "settings.a2a_outbound_url",
            param_names=frozenset(),  # `settings` not a param here
        )
        assert verdict == "allowed"

    def test_classifier_accepts_self_settings_chain_in_method(self) -> None:
        """**T4 R2 P2 contract test:** ``self.settings.a2a_outbound_url``
        in a class method — even though ``self`` is the first method
        parameter, it's a method receiver (Python convention) and
        therefore NOT caller-supplied data. The function-param-root
        refusal explicitly excludes :data:`_METHOD_RECEIVER_NAMES` so
        normal class-method patterns aren't falsely flagged."""
        verdict, reason = self._classify(
            "self.settings.a2a_outbound_url",
            param_names=frozenset({"self"}),
        )
        assert verdict == "allowed", (
            f"self.settings.* chain rejected as function-param-rooted: {reason}"
        )

    def test_classifier_accepts_cls_settings_chain_in_classmethod(self) -> None:
        """``cls.config.a2a_endpoint_url`` in a classmethod — same
        Python-convention exception for the class-method receiver."""
        verdict, _ = self._classify(
            "cls.config.a2a_endpoint_url",
            param_names=frozenset({"cls"}),
        )
        assert verdict == "allowed"

    def test_classifier_accepts_self_verified_card_chain_in_method(self) -> None:
        """``self.verified_card.supported_interfaces[0].url`` in a
        method — verifier-output rebound onto the instance attribute.
        Wait — chain root is ``self``, not ``verified_card``, so the
        verified-card path doesn't fire on its own. But ``self`` is a
        method receiver so the function-param-root refusal also
        doesn't fire. Falls through to "unknown" (the runtime canary
        is the load-bearing half for this shape — implementations
        rebinding the verified card onto an instance attribute should
        either use a local ``verified_card`` var inside the method
        or use the well-known suffix pattern)."""
        verdict, _ = self._classify(
            "self.verified_card.supported_interfaces[0].url",
            param_names=frozenset({"self"}),
        )
        # Documented as "unknown" — not a false-negative; implementer
        # is expected to use a local rebind.
        assert verdict == "unknown"


class TestHttpxCallDetection:
    """Contract tests for :func:`_is_httpx_call` + :func:`_extract_url_arg`.
    These pin the recognition surface — if a future regression drops
    one of the httpx outbound methods from the recognised set, the
    test would silently start passing for that method."""

    def _parse_call(self, source: str) -> ast.Call:
        """Parse a single expression and return the Call node."""
        tree = ast.parse(source)
        expr = tree.body[0]
        assert isinstance(expr, ast.Expr)
        assert isinstance(expr.value, ast.Call)
        return expr.value

    def test_recognises_get_call(self) -> None:
        call = self._parse_call('client.get("https://example.com")')
        assert _is_httpx_call(call) == "get"

    def test_recognises_post_call(self) -> None:
        call = self._parse_call('client.post(url="https://example.com")')
        assert _is_httpx_call(call) == "post"

    def test_recognises_put_call(self) -> None:
        call = self._parse_call('client.put("https://example.com")')
        assert _is_httpx_call(call) == "put"

    def test_recognises_delete_call(self) -> None:
        call = self._parse_call('client.delete("https://example.com")')
        assert _is_httpx_call(call) == "delete"

    def test_recognises_request_method(self) -> None:
        """``client.request('POST', url)`` is the lower-level method;
        also in scope."""
        call = self._parse_call('client.request("POST", "https://example.com")')
        assert _is_httpx_call(call) == "request"

    def test_does_not_recognise_unrelated_method_call(self) -> None:
        """``foo.bar()`` is not an httpx outbound call."""
        call = self._parse_call("foo.bar()")
        assert _is_httpx_call(call) is None

    def test_does_not_recognise_bare_function_call(self) -> None:
        """``get()`` (no client receiver) is not recognised — httpx
        outbound calls are always method calls on a client object."""
        call = self._parse_call('get("https://example.com")')
        assert _is_httpx_call(call) is None

    def test_extract_url_keyword_form(self) -> None:
        """``client.get(url="https://...")`` returns the keyword
        value (works for every method)."""
        call = self._parse_call('client.get(url="https://example.com")')
        url = _extract_url_arg(call, "get")
        assert isinstance(url, ast.Constant)
        assert url.value == "https://example.com"

    def test_extract_url_positional_form(self) -> None:
        """``client.get("https://...")`` returns the first positional
        arg for the URL-at-pos-0 methods (get/post/put/patch/delete)."""
        call = self._parse_call('client.get("https://example.com")')
        url = _extract_url_arg(call, "get")
        assert isinstance(url, ast.Constant)
        assert url.value == "https://example.com"

    def test_extract_url_request_method_takes_url_at_pos_1(self) -> None:
        """**T4 R1 P2 #1 contract test:** ``client.request(method, url)``
        — the URL is at positional arg **1**, not arg 0. The previous
        method-blind extraction returned the literal ``"POST"`` and a
        caller-controlled URL at args[1] would have slipped past."""
        call = self._parse_call('client.request("POST", "https://example.com")')
        url = _extract_url_arg(call, "request")
        assert isinstance(url, ast.Constant)
        assert url.value == "https://example.com"
        # The method name MUST NOT be returned as the URL — that's
        # the bug T4 R1 P2 #1 corrected.
        assert url.value != "POST"

    def test_extract_url_request_with_caller_controlled_url_at_pos_1(self) -> None:
        """**T4 R1 P2 #1 contract test:** the canonical false-negative
        case the reviewer named. ``client.request("POST", target_url)``
        where ``target_url`` is a caller parameter — the static check
        MUST surface ``target_url`` as the URL, not the literal
        ``"POST"``. Combined with the URL-source classifier this is
        the path that catches the caller-controlled URL."""
        call = self._parse_call('client.request("POST", target_url)')
        url = _extract_url_arg(call, "request")
        # The URL extraction returns the AST node at args[1] (the
        # caller-controlled value), NOT args[0] (the method literal).
        assert isinstance(url, ast.Name)
        assert url.id == "target_url"

    def test_extract_url_request_keyword_form_overrides_positional(self) -> None:
        """``client.request("POST", url="https://...")`` — keyword
        form takes precedence regardless of method (matches httpx's
        own resolution)."""
        call = self._parse_call('client.request("POST", url="https://example.com")')
        url = _extract_url_arg(call, "request")
        assert isinstance(url, ast.Constant)
        assert url.value == "https://example.com"

    def test_extract_url_send_returns_none_for_request_object(self) -> None:
        """**T4 R1 P2 #1 contract test:** ``client.send(request_obj)``
        — the first positional arg is a :class:`httpx.Request` object,
        not a URL. Static AST cannot trace into the Request
        construction. Extractor returns None so the caller flags the
        call as 'no statically-identifiable URL argument' and the
        runtime canary takes over."""
        call = self._parse_call("client.send(request_obj)")
        url = _extract_url_arg(call, "send")
        assert url is None

    def test_extract_url_request_with_only_method_arg_returns_none(self) -> None:
        """``client.request("POST")`` — only one positional arg, no
        URL. Returns None (caller flags as unknown). Defensive
        against malformed calls."""
        call = self._parse_call('client.request("POST")')
        url = _extract_url_arg(call, "request")
        assert url is None


class TestHttpxReceiverNarrowing:
    """**T4 R3 P2 contract tests:** the call-detector MUST distinguish
    actual httpx outbound calls from same-named methods on unrelated
    objects. Without this distinction the architecture gate would
    flag normal task-store / header-dict / cache-lookup code in
    T9/T11 as fake URL dispatch.

    Each test parses a single call and asserts whether
    :func:`_is_httpx_call` returns the method name (httpx) or None
    (not flagged).
    """

    def _parse_call(self, source: str) -> ast.Call:
        tree = ast.parse(source)
        expr = tree.body[0]
        assert isinstance(expr, ast.Expr)
        assert isinstance(expr.value, ast.Call)
        return expr.value

    def test_bare_client_name_recognised(self) -> None:
        """``client.get(url)`` — receiver name contains ``client``
        fragment, recognised."""
        call = self._parse_call('client.get("https://example.com")')
        assert _is_httpx_call(call) == "get"

    def test_http_client_name_recognised(self) -> None:
        """``http_client.post(url)`` — receiver name contains
        ``client`` (and ``http``), recognised."""
        call = self._parse_call('http_client.post("https://example.com")')
        assert _is_httpx_call(call) == "post"

    def test_async_client_name_recognised(self) -> None:
        """``async_client.delete(url)`` — receiver name contains
        ``client``, recognised."""
        call = self._parse_call('async_client.delete("https://example.com")')
        assert _is_httpx_call(call) == "delete"

    def test_self_client_attribute_recognised(self) -> None:
        """``self.client.get(url)`` — attribute leaf is ``client``,
        recognised."""
        call = self._parse_call('self.client.get("https://example.com")')
        assert _is_httpx_call(call) == "get"

    def test_self_underscore_http_attribute_recognised(self) -> None:
        """``self._http.post(url)`` — attribute leaf contains ``http``
        fragment, recognised."""
        call = self._parse_call('self._http.post("https://example.com")')
        assert _is_httpx_call(call) == "post"

    def test_self_httpx_client_attribute_recognised(self) -> None:
        """``self.httpx_client.get(url)`` — attribute leaf contains
        ``httpx`` AND ``client``, recognised."""
        call = self._parse_call('self.httpx_client.get("https://example.com")')
        assert _is_httpx_call(call) == "get"

    def test_httpx_module_chain_root_recognised(self) -> None:
        """``httpx.AsyncClient.get(url)`` — chain root is the
        ``httpx`` module (rare but legitimate). The leftmost Name is
        ``httpx``."""
        call = self._parse_call('httpx.AsyncClient.get("https://example.com")')
        assert _is_httpx_call(call) == "get"

    def test_httpx_async_client_constructor_call_recognised(self) -> None:
        """``httpx.AsyncClient().get(url)`` — receiver is a Call
        whose callee chain ends in the httpx module."""
        call = self._parse_call('httpx.AsyncClient().get("https://example.com")')
        assert _is_httpx_call(call) == "get"

    def test_task_store_get_call_NOT_flagged(self) -> None:
        """**T4 R3 P2 critical regression:** ``self._tasks.get(task_id)``
        — task-store dict-like access in T9/T11 task-lifecycle code.
        The receiver attribute leaf is ``_tasks``, which does NOT
        contain any ``_HTTPX_RECEIVER_NAME_FRAGMENTS`` fragment.
        MUST NOT be classified as an httpx call."""
        call = self._parse_call("self._tasks.get(task_id)")
        assert _is_httpx_call(call) is None, (
            "self._tasks.get(task_id) wrongly classified as httpx — "
            "the architecture gate would start flagging normal "
            "task-store accesses as fake URL dispatch"
        )

    def test_headers_get_call_NOT_flagged(self) -> None:
        """**T4 R3 P2 critical regression:** ``headers.get(name)`` —
        header-dict access. Receiver is bare ``headers``, no
        client/http/httpx fragment."""
        call = self._parse_call("headers.get(name)")
        assert _is_httpx_call(call) is None

    def test_mapping_get_call_NOT_flagged(self) -> None:
        """``mapping.get(key)`` — generic dict access. Not flagged."""
        call = self._parse_call("mapping.get(key, default)")
        assert _is_httpx_call(call) is None

    def test_cache_get_call_NOT_flagged(self) -> None:
        """``cache.get(key)`` — cache-lookup pattern. Not flagged."""
        call = self._parse_call("cache.get(key)")
        assert _is_httpx_call(call) is None

    def test_registry_get_call_NOT_flagged(self) -> None:
        """``registry.get(name)`` — registry-lookup pattern. Not
        flagged."""
        call = self._parse_call("registry.get(name)")
        assert _is_httpx_call(call) is None

    def test_store_get_call_NOT_flagged(self) -> None:
        """``store.get(task_id)`` — explicit example named in the
        T4 R3 P2 reviewer correction. Not flagged."""
        call = self._parse_call("store.get(task_id)")
        assert _is_httpx_call(call) is None

    def test_self_underscore_tasks_get_NOT_flagged(self) -> None:
        """``self._tasks.get(task_id)`` — explicit example named in
        the T4 R3 P2 reviewer correction. Not flagged."""
        call = self._parse_call("self._tasks.get(task_id)")
        assert _is_httpx_call(call) is None

    def test_dict_post_method_NOT_flagged(self) -> None:
        """``some_dict.post(key, value)`` — even if a dict-like type
        had a ``post`` method, the receiver name doesn't match. Not
        flagged. Defensive against future user-defined types that
        happen to share method names with httpx."""
        call = self._parse_call("some_dict.post(key, value)")
        assert _is_httpx_call(call) is None

    def test_self_data_get_NOT_flagged(self) -> None:
        """``self.data.get(key)`` — generic instance-data access.
        Receiver attribute leaf is ``data``, no fragment match."""
        call = self._parse_call("self.data.get(key)")
        assert _is_httpx_call(call) is None


class TestHttpxConstructorBindingTracking:
    """**T4 R4 P2 contract tests:** the pre-pass that tracks
    ``transport = httpx.AsyncClient(...)`` / ``self.session =
    httpx.Client(...)`` / ``async with httpx.AsyncClient(...) as
    foo:`` bindings, so renamed httpx clients with non-conforming
    names still match :func:`_is_httpx_receiver`.

    Without this pre-pass, the receiver-narrowing fix from R3 P2
    would create a false-negative path: a maintainer who chose a
    name like ``transport`` / ``outbound`` / ``http2_session``
    would silently escape the architecture gate.
    """

    def _scan_module(self, source: str) -> tuple[frozenset[str], list[str]]:
        """Return ``(module_scope_bindings, violations)`` from scanning
        a synthetic module. Module-scope bindings only — call-site-
        scoped bindings are exercised by other arms below."""
        tree = ast.parse(source)
        module_aliases, ctor_aliases = _collect_httpx_import_aliases(tree)
        module_bindings = _collect_module_scope_bindings(tree, module_aliases, ctor_aliases)
        return module_bindings, _check_caller_controlled_urls(tree, Path("test_stub.py"))

    def test_module_scope_binding_tracked(self) -> None:
        """``transport = httpx.AsyncClient()`` at module scope —
        bound name ``transport`` ends up in the module-scope binding
        set (visible to every call in the module)."""
        source = "import httpx\ntransport = httpx.AsyncClient()\n"
        bindings, _ = self._scan_module(source)
        assert "transport" in bindings

    def test_function_scope_binding_isolated_from_module_scope(self) -> None:
        """``transport = httpx.AsyncClient()`` inside a function —
        T4 R5 P3 reviewer correction: the binding is local to the
        function and does NOT enter the module-scope set. Other
        functions in the same module that happen to use the same
        name do not see this binding."""
        source = (
            "import httpx\n"
            "def make_dispatcher():\n"
            "    transport = httpx.AsyncClient()\n"
            "    return transport\n"
        )
        bindings, _ = self._scan_module(source)
        # Function-local — NOT in module-scope set.
        assert "transport" not in bindings

    def test_self_attribute_binding_NOT_in_module_scope(self) -> None:
        """``self.session = httpx.AsyncClient()`` in __init__ — T4
        R5 P3: lives in CLASS scope, not module scope. Other classes
        / module-level code do not see the binding."""
        source = (
            "import httpx\n"
            "class A2AClient:\n"
            "    def __init__(self):\n"
            "        self.session = httpx.AsyncClient()\n"
        )
        bindings, _ = self._scan_module(source)
        # Class-attribute — NOT in module-scope set.
        assert "session" not in bindings

    def test_annotated_assignment_module_scope_binding_tracked(self) -> None:
        """``transport: httpx.AsyncClient = httpx.AsyncClient()`` at
        module scope — AnnAssign with a value branch."""
        source = "import httpx\ntransport: httpx.AsyncClient = httpx.AsyncClient()\n"
        bindings, _ = self._scan_module(source)
        assert "transport" in bindings

    def test_multiple_target_assign_module_scope_tracked(self) -> None:
        """``a = b = httpx.AsyncClient()`` at module scope — every
        Name target is bound."""
        source = "import httpx\na = b = httpx.AsyncClient()\n"
        bindings, _ = self._scan_module(source)
        assert "a" in bindings
        assert "b" in bindings

    def test_non_httpx_assignment_not_tracked(self) -> None:
        """``transport = SomeOtherType()`` — RHS is not an httpx
        constructor, so the name is NOT added to the bound set.
        Negative control: tracking is precise, not over-broad."""
        source = "transport = SomeOtherType()\n"
        bindings, _ = self._scan_module(source)
        assert "transport" not in bindings

    def test_transport_name_dispatch_url_flagged(self) -> None:
        """**T4 R4 P2 contract test — the canonical case the reviewer
        named.** ``transport = httpx.AsyncClient(); await
        transport.get(target_url)`` — caller-controlled URL slipped
        through the R3 narrowing because ``transport`` doesn't match
        any fragment. The R4 binding-tracking pre-pass catches it.

        T4 R5 P3 update: the binding is function-local (NOT module-
        scope), so the module-scope set returned by ``_scan_module``
        does NOT contain ``transport``. The function-scope lookup
        inside ``_check_caller_controlled_urls`` is what makes the
        call site recognise ``transport`` as httpx, hence the
        violation IS produced."""
        source = (
            "import httpx\n"
            "async def dispatch(target_url):\n"
            "    transport = httpx.AsyncClient()\n"
            "    return await transport.get(target_url)\n"
        )
        bindings, violations = self._scan_module(source)
        # Module-scope set is empty (binding is function-local per
        # R5 P3 scope-aware lookup).
        assert "transport" not in bindings
        # But the violation IS produced because the function-scope
        # lookup picks up the binding when checking the call.
        assert violations, (
            "Renamed httpx client (transport) not flagged — R4 P2 "
            "tracked-binding pre-pass not running OR R5 P3 function-"
            "scope lookup not running"
        )
        assert any("target_url" in v for v in violations)

    def test_outbound_name_dispatch_url_flagged(self) -> None:
        """``outbound = httpx.Client(); outbound.get(target_url)``
        — another non-fragment binding name."""
        source = (
            "import httpx\n"
            "def dispatch(target_url):\n"
            "    outbound = httpx.Client()\n"
            "    return outbound.get(target_url)\n"
        )
        _, violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_self_transport_dispatch_url_flagged(self) -> None:
        """``self.transport = httpx.AsyncClient()`` in __init__ +
        ``self.transport.get(target_url)`` in a method — the
        attribute-leaf binding ``transport`` is tracked, so the
        method call matches."""
        source = (
            "import httpx\n"
            "class A2AClient:\n"
            "    def __init__(self):\n"
            "        self.transport = httpx.AsyncClient()\n"
            "\n"
            "    async def dispatch(self, target_url):\n"
            "        return await self.transport.get(target_url)\n"
        )
        _, violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_async_with_dispatch_url_flagged(self) -> None:
        """``async with httpx.AsyncClient() as session: session.get(target_url)``
        — async-with binding."""
        source = (
            "import httpx\n"
            "async def dispatch(target_url):\n"
            "    async with httpx.AsyncClient() as session:\n"
            "        return await session.get(target_url)\n"
        )
        _, violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_renamed_httpx_with_literal_url_passes(self) -> None:
        """Positive control: a renamed httpx client with a LITERAL
        URL still passes (the binding-tracking only changes which
        calls are SCANNED, not the verdict on already-scanned
        calls)."""
        source = (
            "import httpx\n"
            "async def fetch():\n"
            "    transport = httpx.AsyncClient()\n"
            "    return await transport.get('https://example.com')\n"
        )
        _, violations = self._scan_module(source)
        assert not violations, f"Renamed httpx with literal URL flagged: {violations}"

    def test_non_httpx_renamed_call_still_NOT_flagged(self) -> None:
        """Negative control: a rebinding of a non-httpx type
        (``transport = SomeTransport()``) followed by
        ``transport.get(key)`` is NOT flagged — the binding-
        tracking precisely identifies httpx clients only."""
        source = (
            "class SomeTransport:\n"
            "    def get(self, key): return None\n"
            "\n"
            "def fetch(key):\n"
            "    transport = SomeTransport()\n"
            "    return transport.get(key)\n"
        )
        _, violations = self._scan_module(source)
        assert not violations, (
            f"Non-httpx rebinding wrongly flagged: {violations}. "
            f"Binding-tracking should only catch httpx constructors."
        )


class TestHttpxImportAliasTracking:
    """**T4 R5 P2 contract tests:** the import-alias pre-pass tracks
    ``import httpx as <alias>`` and ``from httpx import {AsyncClient,
    Client} [as <alias>]`` so renamed-import constructor patterns are
    recognised.

    Without alias-tracking, two common forms escape the binding
    pre-pass:

    - ``import httpx as hx; transport = hx.AsyncClient()``
    - ``from httpx import AsyncClient; transport = AsyncClient()``

    In both cases ``transport`` would not be tracked, and a
    ``transport.get(target_url)`` call would silently bypass the
    architecture guard. The alias pre-pass closes this path.
    """

    def _scan_module(self, source: str) -> list[str]:
        tree = ast.parse(source)
        return _check_caller_controlled_urls(tree, Path("test_stub.py"))

    def test_import_httpx_as_alias_tracked(self) -> None:
        """``import httpx as hx`` then ``transport = hx.AsyncClient()``
        — the alias pre-pass adds ``hx`` to the module-alias set so
        the constructor matcher recognises ``hx.AsyncClient``."""
        source = (
            "import httpx as hx\n"
            "async def dispatch(target_url):\n"
            "    transport = hx.AsyncClient()\n"
            "    return await transport.get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations, (
            "import-aliased httpx (hx.AsyncClient) constructor not "
            "tracked — caller-controlled URL slipped past R5 P2 alias "
            "pre-pass"
        )
        assert any("target_url" in v for v in violations)

    def test_from_httpx_import_async_client_tracked(self) -> None:
        """``from httpx import AsyncClient; transport = AsyncClient()``
        — bare-Name constructor pattern; the alias pre-pass adds
        ``AsyncClient`` to the constructor-aliases set."""
        source = (
            "from httpx import AsyncClient\n"
            "async def dispatch(target_url):\n"
            "    transport = AsyncClient()\n"
            "    return await transport.get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations, (
            "from-httpx-import-AsyncClient constructor not tracked — "
            "caller-controlled URL slipped past R5 P2 alias pre-pass"
        )
        assert any("target_url" in v for v in violations)

    def test_from_httpx_import_client_tracked(self) -> None:
        """``from httpx import Client; transport = Client()`` — sync
        Client variant of the bare-Name constructor pattern."""
        source = (
            "from httpx import Client\n"
            "def dispatch(target_url):\n"
            "    transport = Client()\n"
            "    return transport.get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_from_httpx_import_with_rename_tracked(self) -> None:
        """``from httpx import AsyncClient as Async`` then
        ``transport = Async()`` — renamed bare-constructor import."""
        source = (
            "from httpx import AsyncClient as Async\n"
            "async def dispatch(target_url):\n"
            "    transport = Async()\n"
            "    return await transport.get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_unrelated_async_client_call_not_flagged(self) -> None:
        """Negative control: a class named ``AsyncClient`` that is
        NOT imported from httpx must NOT be tracked. The alias
        pre-pass requires ``from httpx import AsyncClient`` or
        equivalent before adding ``AsyncClient`` to the constructor-
        aliases set."""
        source = (
            "class AsyncClient:\n"
            "    def __init__(self):\n"
            "        pass\n"
            "    def get(self, key):\n"
            "        return None\n"
            "\n"
            "def fetch(key):\n"
            "    transport = AsyncClient()\n"
            "    return transport.get(key)\n"
        )
        violations = self._scan_module(source)
        assert not violations, f"Local AsyncClient class wrongly tracked as httpx: {violations}"

    def test_alias_pre_pass_extracts_module_aliases(self) -> None:
        """Direct unit test on :func:`_collect_httpx_import_aliases` —
        ``import httpx as hx`` → module-alias set contains ``hx``
        (plus the always-included ``httpx``)."""
        tree = ast.parse("import httpx as hx\n")
        module_aliases, _ = _collect_httpx_import_aliases(tree)
        assert "hx" in module_aliases
        assert "httpx" in module_aliases  # always included

    def test_alias_pre_pass_extracts_constructor_aliases(self) -> None:
        """Direct unit test: ``from httpx import AsyncClient as Async``
        → constructor-aliases set contains ``Async``."""
        tree = ast.parse("from httpx import AsyncClient as Async\n")
        _, ctor_aliases = _collect_httpx_import_aliases(tree)
        assert "Async" in ctor_aliases

    def test_alias_pre_pass_excludes_unrelated_imports(self) -> None:
        """Direct unit test: ``from somewhere_else import AsyncClient``
        → constructor-aliases set is empty (the import is from a
        non-httpx module)."""
        tree = ast.parse("from somewhere_else import AsyncClient\n")
        _, ctor_aliases = _collect_httpx_import_aliases(tree)
        assert "AsyncClient" not in ctor_aliases


class TestDirectAliasConstructorReceiver:
    """**T4 R6 P2 contract tests:** direct constructor-receiver
    calls (``hx.AsyncClient().get(target_url)`` /
    ``AsyncClient().get(target_url)``) must be flagged.

    Without alias-aware constructor-call receiver handling, these
    forms bypass :func:`_is_httpx_receiver` because the recursive
    Call branch wasn't seeing the alias sets. The R6 P2 fix threads
    ``httpx_module_aliases`` + ``constructor_aliases`` through both
    :func:`_is_httpx_receiver` and :func:`_is_httpx_call`, and
    delegates the Call-receiver case to the alias-aware
    :func:`_is_httpx_constructor_call` matcher.

    These cases are distinct from R5 P2's binding-tracked cases
    (which catch ``transport = hx.AsyncClient(); transport.get(url)``
    via the bound name); R6 P2 covers the variant where the
    constructor result is used directly without a name binding.
    """

    def _scan_module(self, source: str) -> list[str]:
        tree = ast.parse(source)
        return _check_caller_controlled_urls(tree, Path("test_stub.py"))

    def test_aliased_module_direct_constructor_call_flagged(self) -> None:
        """**T4 R6 P2 contract test — first canonical case the
        reviewer named.** ``import httpx as hx`` then
        ``await hx.AsyncClient().get(target_url)`` — direct
        constructor receiver under module alias. The call shape
        skips the binding-pre-pass because no name is bound."""
        source = (
            "import httpx as hx\n"
            "async def dispatch(target_url):\n"
            "    return await hx.AsyncClient().get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations, (
            "Direct hx.AsyncClient() constructor receiver not flagged "
            "— R6 P2 alias-aware Call-receiver detection not running"
        )
        assert any("target_url" in v for v in violations)

    def test_bare_imported_constructor_direct_call_flagged(self) -> None:
        """**T4 R6 P2 contract test — second canonical case the
        reviewer named.** ``from httpx import AsyncClient`` then
        ``await AsyncClient().get(target_url)`` — direct bare-Name
        constructor receiver."""
        source = (
            "from httpx import AsyncClient\n"
            "async def dispatch(target_url):\n"
            "    return await AsyncClient().get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations, (
            "Direct AsyncClient() constructor receiver not flagged "
            "— R6 P2 alias-aware Call-receiver detection not running"
        )
        assert any("target_url" in v for v in violations)

    def test_renamed_bare_imported_constructor_direct_call_flagged(self) -> None:
        """``from httpx import AsyncClient as Async`` then
        ``await Async().get(target_url)`` — renamed bare-Name
        constructor receiver."""
        source = (
            "from httpx import AsyncClient as Async\n"
            "async def dispatch(target_url):\n"
            "    return await Async().get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_aliased_module_direct_sync_client_constructor_flagged(self) -> None:
        """``import httpx as hx`` then ``hx.Client().get(target_url)``
        — sync Client variant of the alias-direct-constructor case."""
        source = (
            "import httpx as hx\n"
            "def dispatch(target_url):\n"
            "    return hx.Client().get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_canonical_httpx_direct_constructor_still_flagged(self) -> None:
        """Positive control: the original
        ``httpx.AsyncClient().get(url)`` case (no alias) MUST still
        be flagged after the R6 P2 alias-aware refactor — the fix is
        precise, not a regression."""
        source = (
            "import httpx\n"
            "async def dispatch(target_url):\n"
            "    return await httpx.AsyncClient().get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_unrelated_class_direct_constructor_NOT_flagged(self) -> None:
        """Negative control: ``SomeOtherType().get(key)`` where
        ``SomeOtherType`` is NOT imported from httpx must NOT be
        flagged. The alias-aware Call-receiver detection requires
        the constructor to match a recognised httpx alias."""
        source = (
            "class SomeOtherType:\n"
            "    def get(self, key):\n"
            "        return None\n"
            "\n"
            "def fetch(key):\n"
            "    return SomeOtherType().get(key)\n"
        )
        violations = self._scan_module(source)
        assert not violations, f"Non-httpx direct-constructor call wrongly flagged: {violations}"

    def test_aliased_constructor_with_literal_url_passes(self) -> None:
        """Positive control: a direct alias-constructor call with a
        LITERAL URL passes — the R6 P2 fix only changes which calls
        get scanned, not the verdict on already-scanned calls."""
        source = (
            "import httpx as hx\n"
            "async def fetch():\n"
            "    return await hx.AsyncClient().get('https://example.com')\n"
        )
        violations = self._scan_module(source)
        assert not violations, f"Aliased direct-constructor with literal URL flagged: {violations}"


class TestHttpxBindingScopeIsolation:
    """**T4 R5 P3 contract tests:** the per-call scope-aware binding
    lookup ensures that a ``session = httpx.AsyncClient()`` in one
    function does NOT leak into ``session.<method>(...)`` calls in
    other functions of the same module.

    Without scope isolation, the previous module-wide binding set
    would have flagged unrelated DB sessions / task sessions as
    httpx, reintroducing the false-positive class R3 P2 was meant
    to eliminate.
    """

    def _scan_module(self, source: str) -> list[str]:
        tree = ast.parse(source)
        return _check_caller_controlled_urls(tree, Path("test_stub.py"))

    def test_function_local_binding_does_not_leak_to_other_functions(self) -> None:
        """``async with httpx.AsyncClient() as session: ...`` in
        function A must NOT make ``session.execute(query)`` in
        function B treat ``session`` as an httpx client. (B's
        ``session`` is a DB session.) But note: ``execute`` isn't
        an outbound httpx method, so this is doubly safe — the
        call would be filtered by the method-name check anyway.
        Use ``.get(key)`` for a more demanding negative."""
        source = (
            "import httpx\n"
            "\n"
            "async def fetch_remote(url):\n"
            "    async with httpx.AsyncClient() as session:\n"
            "        return await session.get(url)\n"
            "\n"
            "def lookup_in_db(session, key):\n"
            "    # Different `session` — actually a DB session.\n"
            "    return session.get(key)\n"
        )
        violations = self._scan_module(source)
        # Only ONE violation expected: the literal-URL fetch_remote
        # call — wait, no — the URL there is a function param, so
        # IT should be flagged. The DB ``session.get(key)`` MUST NOT
        # be flagged.
        assert violations, "fetch_remote with caller-param URL not flagged"
        for v in violations:
            assert "lookup_in_db" not in v, (
                f"DB session.get(key) wrongly flagged as httpx: {v}. "
                f"This is the scope-leak class R5 P3 was meant to fix."
            )

    def test_function_local_httpx_binding_does_NOT_flag_other_function_session_get(
        self,
    ) -> None:
        """The cleanest version of the scope-leak test:
        ``session = httpx.AsyncClient()`` in function A; function B
        has ``session = SomeDBSession(); session.get(key)``. The DB
        ``session.get(key)`` MUST NOT be flagged."""
        source = (
            "import httpx\n"
            "\n"
            "async def fetch_remote():\n"
            "    session = httpx.AsyncClient()\n"
            "    return await session.get('https://example.com')\n"
            "\n"
            "def lookup_in_db(key):\n"
            "    session = SomeDBSession()\n"
            "    return session.get(key)\n"
        )
        violations = self._scan_module(source)
        # The first function uses a literal URL — no violation there.
        # The second function uses a DB session — must NOT be flagged
        # as httpx because the ``session = httpx.AsyncClient()``
        # binding is function-local to fetch_remote.
        assert not violations, (
            f"Scope-leak violation: {violations}. R5 P3 scope-aware binding lookup not running."
        )

    def test_class_attribute_binding_does_not_leak_to_unrelated_class(self) -> None:
        """``self.session = httpx.AsyncClient()`` in class A must
        NOT make ``self.session.get(key)`` in class B treat
        ``session`` as an httpx client (B's ``self.session`` is
        a DB session)."""
        source = (
            "import httpx\n"
            "\n"
            "class A2AClient:\n"
            "    def __init__(self):\n"
            "        self.session = httpx.AsyncClient()\n"
            "\n"
            "    async def fetch(self):\n"
            "        return await self.session.get('https://example.com')\n"
            "\n"
            "class DbRepository:\n"
            "    def __init__(self):\n"
            "        self.session = SomeDBSession()\n"
            "\n"
            "    def lookup(self, key):\n"
            "        return self.session.get(key)\n"
        )
        violations = self._scan_module(source)
        # A2AClient.fetch uses a literal URL → no violation.
        # DbRepository.lookup uses DB session → must NOT be flagged.
        assert not violations, (
            f"Scope-leak violation across classes: {violations}. "
            f"R5 P3 class-scope isolation not running."
        )

    def test_module_scope_binding_visible_everywhere(self) -> None:
        """Positive control: a ``session = httpx.AsyncClient()`` at
        MODULE scope IS visible everywhere. Function B's
        ``session.get(key)`` IS flagged because the module-scope
        binding makes ``session`` an httpx client throughout the
        whole module. This documents the intentional scope rule:
        module-scope = global; function-scope = function-local;
        class-scope = class-internal."""
        source = (
            "import httpx\n"
            "\n"
            "session = httpx.AsyncClient()\n"
            "\n"
            "async def fetch_a(target_url):\n"
            "    return await session.get(target_url)\n"
            "\n"
            "async def fetch_b(target_url):\n"
            "    return await session.get(target_url)\n"
        )
        violations = self._scan_module(source)
        # Both function calls flag — module-scope binding makes
        # ``session`` an httpx client everywhere.
        assert violations, "Module-scope httpx binding not visible to functions"
        # Both fetch_a and fetch_b's caller URL should be flagged.
        flagged_lines = {v.split(":")[1].split(" ")[0] for v in violations}
        # Two flagged calls → two distinct line numbers.
        assert len(flagged_lines) >= 2, (
            f"Expected 2 violations (one per function); got: {violations}"
        )

    def test_class_method_binding_visible_to_other_method_same_class(self) -> None:
        """Positive control: ``self.session = httpx.AsyncClient()``
        in __init__ IS visible to ``self.session.get(...)`` in any
        other method of the same class. Class-scope is the right
        scope for instance-attribute bindings — ``__init__`` and
        the dispatch method see the same ``self.session``."""
        source = (
            "import httpx\n"
            "\n"
            "class A2AClient:\n"
            "    def __init__(self):\n"
            "        self.session = httpx.AsyncClient()\n"
            "\n"
            "    async def dispatch(self, target_url):\n"
            "        return await self.session.get(target_url)\n"
        )
        violations = self._scan_module(source)
        assert violations, (
            "self.session bound in __init__ not visible to dispatch — "
            "class-scope lookup not running"
        )
        assert any("target_url" in v for v in violations)


class TestEndToEndModuleScanning:
    """Synthetic-module scenarios that exercise the full pipeline
    (collector → import-walker → call-walker → URL classifier).

    Each test plants a small Python file in ``tmp_path`` and asserts
    the violation set matches expectation."""

    def _scan_file(self, path: Path) -> list[str]:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        return _check_caller_controlled_urls(tree, path)

    def test_module_with_literal_url_passes(self, tmp_path: Path) -> None:
        """A module that calls ``client.get("https://...")`` with a
        literal URL passes."""
        path = tmp_path / "a2a_test.py"
        path.write_text(
            'async def fetch(client):\n    return await client.get("https://example.com/path")\n',
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, f"Literal URL flagged: {violations}"

    def test_module_with_caller_param_url_fails(self, tmp_path: Path) -> None:
        """A module that calls ``client.get(target_url)`` where
        ``target_url`` is a function parameter MUST be flagged."""
        path = tmp_path / "a2a_bad.py"
        path.write_text(
            "async def dispatch(client, target_url):\n    return await client.get(target_url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, "Caller-controlled URL not flagged"
        assert any("target_url" in v for v in violations)

    def test_module_with_request_body_url_fails(self, tmp_path: Path) -> None:
        """A module that calls ``client.post(url=request.body.url)``
        MUST be flagged."""
        path = tmp_path / "a2a_inbound.py"
        path.write_text(
            "async def forward(client, request):\n"
            "    return await client.post(url=request.body.url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations
        assert any("inbound" in v.lower() or "request" in v.lower() for v in violations)

    def test_module_with_agent_card_url_passes(self, tmp_path: Path) -> None:
        """A module that calls
        ``client.post(url=verified_card.supported_interfaces[0].url)``
        passes — the verifier's return value is rebound through the
        ``verified_card`` name (the verifier-output allow-list root)
        before the dispatch URL is constructed.

        T4 R2 P2 reviewer correction: the previous shape used a bare
        ``card`` parameter, which is now correctly refused as
        function-param-rooted. Real implementations MUST rebind the
        verifier's output through ``verified_card`` /
        ``verified_agent_card``."""
        path = tmp_path / "a2a_dispatch.py"
        path.write_text(
            "async def dispatch(client, raw_card):\n"
            "    verified_card = trust_gate.verify_jws_blob(raw_card.jws)\n"
            "    return await client.post(url=verified_card.supported_interfaces[0].url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, f"Verifier-output AgentCard URL flagged: {violations}"

    def test_module_with_settings_field_url_passes(self, tmp_path: Path) -> None:
        """A module that calls
        ``await self.client.get(self.settings.a2a_outbound_url)`` from
        a class method passes. ``self`` is a method-receiver name
        (excluded from the function-param-root refusal per
        :data:`_METHOD_RECEIVER_NAMES`); the chain leaf
        ``a2a_outbound_url`` matches the settings-shape allow path.

        T4 R2 P2 reviewer correction: the previous shape used
        ``settings`` as a function parameter, which is now correctly
        refused. Real implementations bind settings either at
        ``self.settings`` (class methods) or at module scope
        (free functions)."""
        path = tmp_path / "a2a_settings.py"
        path.write_text(
            "class A2AClient:\n"
            "    async def fetch(self):\n"
            "        return await self.client.get(self.settings.a2a_outbound_url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, f"self-rooted settings URL flagged: {violations}"

    def test_module_with_module_scope_settings_passes(self, tmp_path: Path) -> None:
        """A module that calls ``client.get(settings.a2a_outbound_url)``
        with ``settings`` as a module-level binding (NOT a function
        parameter) passes — the chain root ``settings`` is not in
        the enclosing function's parameter set."""
        path = tmp_path / "a2a_module_scope_settings.py"
        path.write_text(
            "from cognic_agentos.core.config import build_settings_without_env_file\n"
            "settings = build_settings_without_env_file()\n"
            "\n"
            "async def fetch(client):\n"
            "    return await client.get(settings.a2a_outbound_url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, f"Module-scope settings URL flagged: {violations}"

    def test_module_with_well_known_pattern_passes(self, tmp_path: Path) -> None:
        """A module that constructs the well-known agent-card discovery
        URL via f-string from a verifier-output card's origin. The
        f-string heuristic recognises the well-known suffix pattern;
        the runtime canary asserts ``verified_card.origin`` traces to
        a verified source.

        T4 R2 P2 reviewer correction: the previous shape used
        ``card.origin`` from a function parameter, which is now
        (correctly) classified as function-param-rooted and refused.
        Real implementations MUST construct discovery URLs from
        verifier-output names."""
        path = tmp_path / "a2a_discovery.py"
        path.write_text(
            "async def fetch_card(client, raw_origin_blob):\n"
            "    verified_card = trust_gate.verify_jws_blob(raw_origin_blob)\n"
            "    return await client.get(\n"
            '        f"{verified_card.origin}/.well-known/agent-card.json"\n'
            "    )\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, f"Well-known discovery (verifier-rebound) flagged: {violations}"

    def test_module_with_well_known_pattern_from_function_param_card_fails(
        self, tmp_path: Path
    ) -> None:
        """**T4 R2 P2 end-to-end regression:** the canonical false-
        negative case. ``f"{card.origin}/.well-known/agent-card.json"``
        where ``card`` is a function parameter — chain root is a
        function parameter, so even the well-known suffix pattern
        cannot rescue the URL. The f-string aggregator sees a
        forbidden interpolation and the verdict is forbidden
        regardless of the suffix."""
        path = tmp_path / "a2a_discovery_bad.py"
        path.write_text(
            "async def fetch_card(client, card):\n"
            "    return await client.get(\n"
            '        f"{card.origin}/.well-known/agent-card.json"\n'
            "    )\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, "Well-known pattern with function-param card root not flagged"
        assert any("function parameter" in v.lower() or "card" in v for v in violations)

    def test_module_with_function_param_card_supported_interfaces_fails(
        self, tmp_path: Path
    ) -> None:
        """**T4 R2 P2 end-to-end regression:** the exact case the
        reviewer named — ``client.post(url=target_card.supported_interfaces[0].url)``
        where ``target_card`` is a function parameter. Chain LOOKS
        verifier-shaped but the root is caller-supplied. Refused."""
        path = tmp_path / "a2a_dispatch_bad.py"
        path.write_text(
            "async def dispatch(client, target_card):\n"
            "    return await client.post(url=target_card.supported_interfaces[0].url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, "Function-param-rooted card-shaped chain not flagged at module scope"
        assert any("target_card" in v for v in violations)

    def test_module_with_task_store_get_NOT_flagged(self, tmp_path: Path) -> None:
        """**T4 R3 P2 end-to-end regression:** a module with
        ``self._tasks.get(task_id)`` (the canonical T9/T11 task-store
        pattern) MUST NOT be flagged. Receiver name ``_tasks`` is not
        an httpx receiver per :data:`_HTTPX_RECEIVER_NAME_FRAGMENTS`,
        so the call is ignored entirely — even though ``task_id`` is
        a function parameter."""
        path = tmp_path / "a2a_task_store.py"
        path.write_text(
            "class TaskLifecycle:\n"
            "    def __init__(self):\n"
            "        self._tasks = {}\n"
            "\n"
            "    async def get_task(self, task_id):\n"
            "        return self._tasks.get(task_id)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, (
            f"Task-store get(task_id) wrongly flagged as httpx URL: {violations}. "
            f"This is the regression class the T4 R3 P2 reviewer-correction "
            f"narrows the call detector to prevent."
        )

    def test_module_with_headers_dict_get_NOT_flagged(self, tmp_path: Path) -> None:
        """**T4 R3 P2 end-to-end regression:** a module with
        ``headers.get(name)`` (the canonical header-dict pattern in
        T9 inbound-handling code) MUST NOT be flagged."""
        path = tmp_path / "a2a_headers.py"
        path.write_text(
            "def extract_header(headers, name):\n    return headers.get(name)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert not violations, f"headers.get(name) wrongly flagged as httpx URL: {violations}"

    def test_module_with_real_httpx_call_after_dict_calls_still_flagged(
        self, tmp_path: Path
    ) -> None:
        """**T4 R3 P2 end-to-end regression — positive control:** a
        module that has BOTH dict-like ``.get()`` calls AND a real
        httpx outbound call still flags the httpx call. The
        receiver-narrowing is precise, not over-broad."""
        path = tmp_path / "a2a_mixed.py"
        path.write_text(
            "class A2AClient:\n"
            "    def __init__(self):\n"
            "        self._tasks = {}\n"
            "        self.client = None\n"
            "\n"
            "    async def get_task_and_dispatch(self, task_id, target_url):\n"
            "        cached = self._tasks.get(task_id)  # NOT flagged (dict)\n"
            "        return await self.client.get(target_url)  # flagged\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, (
            "Real httpx call after dict-like get NOT flagged — receiver-narrowing was over-broad"
        )
        # Exactly one violation — the httpx call. The dict call must
        # NOT generate a violation.
        assert len(violations) == 1, (
            f"Expected exactly 1 violation (the httpx call); got {len(violations)}: {violations}"
        )
        assert "target_url" in violations[0]
        # And the violation MUST cite the httpx call, not the dict call.
        assert "self._tasks.get" not in violations[0]

    def test_module_with_request_method_caller_url_at_pos_1_fails(self, tmp_path: Path) -> None:
        """**T4 R1 P2 #1 end-to-end regression:** the canonical false-
        negative case the reviewer named.
        ``client.request("POST", target_url)`` — caller-controlled
        URL at positional arg 1. The previous method-blind
        ``_extract_url_arg`` returned the literal ``"POST"`` (allowed);
        the method-aware extractor returns ``target_url`` (forbidden
        because it's a function parameter).
        """
        path = tmp_path / "a2a_request_method.py"
        path.write_text(
            "async def dispatch(client, target_url):\n"
            '    return await client.request("POST", target_url)\n',
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, (
            "client.request(method, caller_url) not flagged — the URL "
            "at args[1] should have been classified as caller-supplied"
        )
        assert any("target_url" in v for v in violations), (
            f"Violation present but didn't name target_url: {violations}"
        )

    def test_module_with_request_method_caller_url_kwarg_fails(self, tmp_path: Path) -> None:
        """``client.request("POST", url=target_url)`` — keyword-form
        is still caught (it was working pre-R1 P2 #1, but pin
        the regression so the keyword path doesn't drift)."""
        path = tmp_path / "a2a_request_kwarg.py"
        path.write_text(
            "async def dispatch(client, target_url):\n"
            '    return await client.request("POST", url=target_url)\n',
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations
        assert any("target_url" in v for v in violations)

    def test_module_with_send_call_flagged_as_unknown(self, tmp_path: Path) -> None:
        """**T4 R1 P2 #1 end-to-end regression:** ``client.send(req)``
        — first positional arg is a Request object, not a URL.
        Static AST cannot trace into the Request construction.
        Caller flags as 'no statically-identifiable URL argument'
        and the runtime canary takes over."""
        path = tmp_path / "a2a_send.py"
        path.write_text(
            "async def dispatch(client, request_obj):\n    return await client.send(request_obj)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, (
            "client.send(request_obj) not flagged — Request-object "
            "calls should be flagged as unknown URL source per "
            "_HTTPX_URL_AS_REQUEST_OBJECT contract"
        )
        assert any("no statically-identifiable URL argument" in v for v in violations), (
            f"client.send violation present but with wrong message: {violations}"
        )

    def test_module_with_inbound_supported_interfaces_chain_fails(self, tmp_path: Path) -> None:
        """**T4 R1 P2 #2 end-to-end regression:** the ambiguous-chain
        false-negative the reviewer named. A module that calls
        ``client.post(url=request.supported_interfaces[0].url)`` —
        chain LOOKS card-shaped but the root is the inbound A2A
        request. The previous allow-list ordering accepted this;
        the corrected ordering refuses it."""
        path = tmp_path / "a2a_inbound_card_shape.py"
        path.write_text(
            "async def forward(client, request):\n"
            "    return await client.post(url=request.supported_interfaces[0].url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations, "Inbound chain with card-shaped suffix not flagged"
        assert any("request" in v.lower() and "inbound" in v.lower() for v in violations), (
            f"Violation present but didn't name inbound root: {violations}"
        )

    def test_module_with_message_agent_card_url_chain_fails(self, tmp_path: Path) -> None:
        """**T4 R1 P2 #2 end-to-end regression:** ``message.agent_card.url``
        — chain LOOKS like ``card.url`` access, but the root is
        ``message`` (caller-controlled inbound A2A envelope). Same
        hazard class as the supported_interfaces case."""
        path = tmp_path / "a2a_inbound_card_url.py"
        path.write_text(
            "async def forward(client, message):\n"
            "    return await client.get(message.agent_card.url)\n",
            encoding="utf-8",
        )
        violations = self._scan_file(path)
        assert violations
        assert any("message" in v.lower() and "inbound" in v.lower() for v in violations)
