"""Bounded Python AST and IPython-structure detection without code execution."""

from __future__ import annotations

import ast
import builtins
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from agent_guardrail.detectors._patterns import occurrence_fingerprint
from agent_guardrail.models import Detection, DetectionContext

MAX_PYTHON_AST_DETECTIONS = 64

PYTHON_AST_IPYTHON_TYPES = frozenset(
    {
        "ipython_cell_magic",
        "ipython_help_query",
        "ipython_line_magic",
        "ipython_shell_escape",
        "python_builtin",
        "python_dangerous_import",
        "python_dynamic_execution",
        "python_filesystem_access",
        "python_function_call",
        "python_import",
        "python_network_access",
        "python_process_execution",
        "python_syntax_error",
    }
)

_BUILTIN_NAMES = frozenset(dir(builtins))
_DANGEROUS_IMPORT_ROOTS = frozenset(
    {
        "aiohttp",
        "asyncio",
        "asyncssh",
        "cmd",
        "http",
        "httpx",
        "importlib",
        "mechanize",
        "os",
        "pathlib",
        "requests",
        "shutil",
        "socket",
        "subprocess",
        "urllib",
    }
)
_DYNAMIC_CALLS = frozenset(
    {
        "__import__",
        "builtins.__import__",
        "builtins.compile",
        "builtins.eval",
        "builtins.exec",
        "compile",
        "eval",
        "exec",
        "importlib.import_module",
    }
)
_PROCESS_CALLS = frozenset(
    {
        "os.popen",
        "os.system",
        "pty.spawn",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.Popen",
        "subprocess.run",
    }
)
_FILESYSTEM_CALLS = frozenset(
    {
        "builtins.open",
        "open",
        "os.remove",
        "os.removedirs",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.unlink",
        "pathlib.Path.open",
        "pathlib.Path.rename",
        "pathlib.Path.replace",
        "pathlib.Path.rmdir",
        "pathlib.Path.unlink",
        "Path.open",
        "Path.rename",
        "Path.replace",
        "Path.rmdir",
        "Path.unlink",
        "shutil.move",
        "shutil.rmtree",
    }
)
_NETWORK_PREFIXES = (
    "aiohttp.",
    "asyncssh.",
    "http.client.",
    "httpx.",
    "mechanize.",
    "requests.",
    "socket.",
    "urllib.",
)
_IPYTHON_CELL_MAGIC = re.compile(r"^(?P<indent>[ \t]*)%%(?P<name>[A-Za-z][\w-]*)")
_IPYTHON_LINE_MAGIC = re.compile(
    r"^(?P<prefix>[ \t]*(?:[A-Za-z_][\w.]*[ \t]*=[ \t]*)?)"
    r"%(?P<name>[A-Za-z][\w-]*)"
)
_IPYTHON_SHELL = re.compile(
    r"^(?P<prefix>[ \t]*(?:[A-Za-z_][\w.]*[ \t]*=[ \t]*)?)!"
)
_IPYTHON_HELP = re.compile(
    r"^[ \t]*(?P<query>(?:[A-Za-z_][\w.]*\?\??|\?\??[A-Za-z_][\w.]*))"
    r"[ \t]*(?:#.*)?$"
)
_PYTHON_BODY_CELL_MAGICS = frozenset({"capture", "prun", "time", "timeit"})


@dataclass(frozen=True, slots=True)
class _Candidate:
    start: int
    end: int
    type: str
    confidence: float
    priority: int = 0


_ScopeKind = Literal["module", "function", "class", "lambda", "comprehension"]


@dataclass(frozen=True, slots=True)
class _BranchToken:
    control_type: str
    control_start: tuple[int, int]
    control_end: tuple[int, int]
    label: str


@dataclass(frozen=True, slots=True)
class _NameBinding:
    position: tuple[int, int, int]
    canonical_name: str | None
    always_active: bool = False
    branch_path: tuple[_BranchToken, ...] = ()


@dataclass(frozen=True, slots=True)
class _ScopeBindings:
    kind: _ScopeKind
    bindings: dict[str, tuple[_NameBinding, ...]]
    external_names: frozenset[str] = frozenset()


class PythonASTIPythonDetector:
    """Extract finite Python/IPython facts using only local parsing.

    The input is never imported or executed. IPython syntax is recognized by a
    small, deterministic preprocessor that preserves character offsets before
    the remaining Python source is passed to :mod:`ast`.
    """

    name = "python_ast_ipython"
    version = "2"

    async def detect(
        self,
        text: str,
        *,
        context: DetectionContext,
    ) -> list[Detection]:
        python_text, candidates = _preprocess_ipython(text)
        try:
            tree = ast.parse(python_text, mode="exec")
        except SyntaxError as exc:
            candidates.append(_syntax_error_candidate(text, exc))
        else:
            visitor = _PythonFactVisitor(python_text)
            visitor.visit(tree)
            candidates.extend(visitor.candidates)
        return _detections_from_candidates(text, candidates, context=context)


class _PythonFactVisitor(ast.NodeVisitor):
    def __init__(self, text: str) -> None:
        self._text = text
        self._lines = text.splitlines(keepends=True)
        self._line_starts = _line_starts(text)
        self._scopes: list[_ScopeBindings] = []
        self._scope_branch_paths: list[list[_BranchToken]] = []
        self.candidates: list[_Candidate] = []

    def visit_Module(self, node: ast.Module) -> None:  # noqa: N802
        self._visit_scoped_body("module", node.body)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            span = self._span(alias, fallback=node)
            self._add(*span, "python_import", 1.0)
            if _module_root(alias.name) in _DANGEROUS_IMPORT_ROOTS:
                self._add(*span, "python_dangerous_import", 0.94, priority=10)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        span = self._span(node)
        self._add(*span, "python_import", 1.0)
        module = node.module
        if node.level == 0 and module is not None:
            if _module_root(module) in _DANGEROUS_IMPORT_ROOTS:
                self._add(*span, "python_dangerous_import", 0.94, priority=10)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for type_parameter in node.type_params:
            self.visit(type_parameter)
        self._visit_scoped_body("class", node.body)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        self._visit_argument_defaults(node.args)
        scope = _collect_lambda_scope_bindings(node)
        self._scopes.append(scope)
        self._scope_branch_paths.append([])
        try:
            self.visit(node.body)
        finally:
            self._scope_branch_paths.pop()
            self._scopes.pop()

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self.visit(node.test)
        self._visit_branch_suite(node, "body", node.body)
        self._visit_branch_suite(node, "else", node.orelse)

    def visit_IfExp(self, node: ast.IfExp) -> None:  # noqa: N802
        self.visit(node.test)
        self._visit_branch_node(node, "body", node.body)
        self._visit_branch_node(node, "else", node.orelse)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:  # noqa: N802
        if not node.values:
            return
        self.visit(node.values[0])
        pushed = 0
        try:
            for index, value in enumerate(node.values[1:], start=1):
                self._push_branch(node, f"value-{index}")
                pushed += 1
                self.visit(value)
        finally:
            for _ in range(pushed):
                self._pop_branch()

    def visit_Try(self, node: ast.Try) -> None:  # noqa: N802
        self._visit_try_node(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:  # noqa: N802
        self._visit_try_node(node)

    def visit_Match(self, node: ast.Match) -> None:  # noqa: N802
        self.visit(node.subject)
        for index, case in enumerate(node.cases):
            self._push_branch(node, f"case-{index}")
            try:
                self.visit(case.pattern)
                if case.guard is not None:
                    self.visit(case.guard)
                for statement in case.body:
                    self.visit(statement)
            finally:
                self._pop_branch()

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self._visit_loop(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self._visit_loop(node)

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        self.visit(node.test)
        self._visit_branch_suite(node, "body", node.body)
        self._visit_branch_suite(node, "else", node.orelse)

    def visit_ListComp(self, node: ast.ListComp) -> None:  # noqa: N802
        self._visit_comprehension(node, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:  # noqa: N802
        self._visit_comprehension(node, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        self._visit_comprehension(node, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:  # noqa: N802
        self._visit_comprehension(node, (node.key, node.value))

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if (
            isinstance(node.ctx, ast.Load)
            and any(
                _is_builtin_name(name)
                for name in self._resolve_names(node.id, position=node)
            )
        ):
            self._add(*self._span(node), "python_builtin", 1.0)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        span = self._span(node.func, fallback=node)
        self._add(*span, "python_function_call", 1.0)
        call_names = _call_names(node.func, resolve_names=self._resolve_names)
        if any(call_name in _DYNAMIC_CALLS for call_name in call_names):
            self._add(*span, "python_dynamic_execution", 0.99, priority=30)
        if any(
            call_name in _PROCESS_CALLS or call_name.startswith("subprocess.")
            for call_name in call_names
        ):
            self._add(*span, "python_process_execution", 0.98, priority=30)
        if any(call_name in _FILESYSTEM_CALLS for call_name in call_names):
            self._add(*span, "python_filesystem_access", 0.92, priority=20)
        if any(call_name.startswith(_NETWORK_PREFIXES) for call_name in call_names):
            self._add(*span, "python_network_access", 0.92, priority=20)
        self.generic_visit(node)

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_argument_defaults(node.args)
        self._visit_argument_annotations(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        for type_parameter in node.type_params:
            self.visit(type_parameter)
        scope = _collect_scope_bindings("function", node.body, arguments=node.args)
        self._scopes.append(scope)
        self._scope_branch_paths.append([])
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._scope_branch_paths.pop()
            self._scopes.pop()

    def _visit_argument_defaults(self, arguments: ast.arguments) -> None:
        for default in arguments.defaults:
            self.visit(default)
        for default in arguments.kw_defaults:
            if default is not None:
                self.visit(default)

    def _visit_argument_annotations(self, arguments: ast.arguments) -> None:
        positional = (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
        for argument in positional:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            self.visit(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            self.visit(arguments.kwarg.annotation)

    def _visit_scoped_body(
        self,
        kind: _ScopeKind,
        body: list[ast.stmt],
    ) -> None:
        self._scopes.append(_collect_scope_bindings(kind, body))
        self._scope_branch_paths.append([])
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._scope_branch_paths.pop()
            self._scopes.pop()

    def _visit_comprehension(
        self,
        node: ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp,
        result_expressions: tuple[ast.expr, ...],
    ) -> None:
        generators = node.generators
        if not generators:
            return
        self.visit(generators[0].iter)
        pushed_scopes = 0
        try:
            for index, generator in enumerate(generators):
                if index > 0:
                    self.visit(generator.iter)
                self._scopes.append(
                    _always_shadowed_scope(
                        "comprehension",
                        _target_names(generator.target),
                    )
                )
                self._scope_branch_paths.append([])
                pushed_scopes += 1
                for condition in generator.ifs:
                    self.visit(condition)
            for expression in result_expressions:
                self.visit(expression)
        finally:
            for _ in range(pushed_scopes):
                self._scope_branch_paths.pop()
                self._scopes.pop()

    def _resolve_names(
        self,
        name: str,
        position: ast.AST,
    ) -> frozenset[str]:
        query_position = _node_start_position(position)
        crossed_function_scope = False
        indexed_scopes = zip(
            range(len(self._scopes) - 1, -1, -1),
            reversed(self._scopes),
            strict=True,
        )
        for scope_index, scope in indexed_scopes:
            if scope.kind == "class" and crossed_function_scope:
                continue
            bindings = scope.bindings.get(name, ())
            query_path = tuple(self._scope_branch_paths[scope_index])
            if name in scope.external_names:
                local_resolution = _resolve_scope_binding_names(
                    bindings,
                    query_position=query_position,
                    query_path=query_path,
                )
                if local_resolution is not None and not _has_only_may_bindings(
                    bindings,
                    query_position=query_position,
                    query_path=query_path,
                ):
                    return local_resolution
                outer_resolution = self._resolve_outer_names(
                    name,
                    start_scope_index=scope_index - 1,
                    query_position=query_position,
                )
                if local_resolution is None:
                    return outer_resolution
                return frozenset(local_resolution | outer_resolution)
            elif bindings:
                possible_names = _resolve_scope_binding_names(
                    bindings,
                    query_position=query_position,
                    query_path=query_path,
                )
                if possible_names is not None:
                    return possible_names
                future_aliases = frozenset(
                    binding.canonical_name
                    for binding in bindings
                    if binding.canonical_name is not None
                    and _binding_path_relation(
                        binding.branch_path,
                        query_path,
                        query_position=query_position,
                    )
                    == "must"
                )
                if future_aliases:
                    return future_aliases
            if scope.kind in {"function", "lambda", "comprehension"}:
                crossed_function_scope = True
        return frozenset({name})

    def _resolve_outer_names(
        self,
        name: str,
        *,
        start_scope_index: int,
        query_position: tuple[int, int, int],
    ) -> frozenset[str]:
        crossed_function_scope = True
        for scope_index in range(start_scope_index, -1, -1):
            scope = self._scopes[scope_index]
            if scope.kind == "class" and crossed_function_scope:
                continue
            bindings = scope.bindings.get(name, ())
            if bindings:
                resolved = _resolve_scope_binding_names(
                    bindings,
                    query_position=query_position,
                    query_path=tuple(self._scope_branch_paths[scope_index]),
                )
                if resolved is not None:
                    return resolved
            if scope.kind in {"function", "lambda", "comprehension"}:
                crossed_function_scope = True
        return frozenset({name})

    def _visit_branch_suite(
        self,
        control: ast.AST,
        label: str,
        suite: Iterable[ast.stmt],
    ) -> None:
        statements = tuple(suite)
        if not statements:
            return
        self._push_branch(control, label)
        try:
            for statement in statements:
                self.visit(statement)
        finally:
            self._pop_branch()

    def _visit_branch_node(
        self,
        control: ast.AST,
        label: str,
        node: ast.AST,
    ) -> None:
        self._push_branch(control, label)
        try:
            self.visit(node)
        finally:
            self._pop_branch()

    def _visit_try_node(self, node: ast.Try | ast.TryStar) -> None:
        self._push_branch(node, "body")
        try:
            for statement in node.body:
                self.visit(statement)
            self._push_branch(node, "else")
            try:
                for statement in node.orelse:
                    self.visit(statement)
            finally:
                self._pop_branch()
        finally:
            self._pop_branch()
        for index, handler in enumerate(node.handlers):
            self._visit_branch_node(node, f"handler-{index}", handler)
        for statement in node.finalbody:
            self.visit(statement)

    def _visit_loop(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._push_branch(node, "body")
        try:
            self.visit(node.target)
            for statement in node.body:
                self.visit(statement)
        finally:
            self._pop_branch()
        self._visit_branch_suite(node, "else", node.orelse)

    def _push_branch(self, control: ast.AST, label: str) -> None:
        self._scope_branch_paths[-1].append(_branch_token(control, label))

    def _pop_branch(self) -> None:
        self._scope_branch_paths[-1].pop()

    def _span(self, node: ast.AST, *, fallback: ast.AST | None = None) -> tuple[int, int]:
        selected = node
        if not all(
            hasattr(selected, attribute)
            for attribute in ("lineno", "col_offset", "end_lineno", "end_col_offset")
        ):
            if fallback is None:
                raise ValueError("Python AST node has no source location")
            selected = fallback
        start = _ast_offset(
            self._lines,
            self._line_starts,
            selected.lineno,  # type: ignore[attr-defined]
            selected.col_offset,  # type: ignore[attr-defined]
        )
        end = _ast_offset(
            self._lines,
            self._line_starts,
            selected.end_lineno,  # type: ignore[attr-defined]
            selected.end_col_offset,  # type: ignore[attr-defined]
        )
        if end <= start:
            end = min(len(self._text), start + 1)
        return start, end

    def _add(
        self,
        start: int,
        end: int,
        detection_type: str,
        confidence: float,
        *,
        priority: int = 0,
    ) -> None:
        self.candidates.append(
            _Candidate(start, end, detection_type, confidence, priority)
        )


class _ScopeBindingCollector(ast.NodeVisitor):
    """Collect lexical bindings without descending into nested scopes."""

    def __init__(self, *, parameter_names: Iterable[str] = ()) -> None:
        self._bindings: dict[str, list[_NameBinding]] = {}
        self._external_declarations: set[str] = set()
        self._sequence = 0
        self._branch_path: list[_BranchToken] = []
        for name in parameter_names:
            self._bind(name, None, always_active=True)

    def build(self, kind: _ScopeKind) -> _ScopeBindings:
        return _ScopeBindings(
            kind=kind,
            bindings={
                name: tuple(sorted(bindings, key=lambda item: item.position))
                for name, bindings in self._bindings.items()
            },
            external_names=frozenset(self._external_declarations),
        )

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            if alias.asname is not None:
                self._bind_alias(alias.asname, alias.name, position=node)
            else:
                root = _module_root(alias.name)
                self._bind_alias(root, root, position=node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            if node.level == 0 and module is not None:
                self._bind_alias(
                    local_name,
                    f"{module}.{alias.name}",
                    position=node,
                )
            else:
                self._bind_other(local_name, position=node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target, position=node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
        self._bind_target(node.target, position=node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:  # noqa: N802
        self.visit(node.value)
        self._bind_target(node.target, position=node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:  # noqa: N802
        self.visit(node.value)
        self._bind_target(node.target, position=node)

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self.visit(node.test)
        self._visit_branch_suite(node, "body", node.body)
        self._visit_branch_suite(node, "else", node.orelse)
        if node.orelse:
            self._bind_exhaustive_safe_if_kills(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:  # noqa: N802
        self.visit(node.test)
        self._visit_branch_node(node, "body", node.body)
        self._visit_branch_node(node, "else", node.orelse)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:  # noqa: N802
        if not node.values:
            return
        self.visit(node.values[0])
        pushed = 0
        try:
            for index, value in enumerate(node.values[1:], start=1):
                self._push_branch(node, f"value-{index}")
                pushed += 1
                self.visit(value)
        finally:
            for _ in range(pushed):
                self._pop_branch()

    def visit_Try(self, node: ast.Try) -> None:  # noqa: N802
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:  # noqa: N802
        self._visit_try(node)

    def visit_Match(self, node: ast.Match) -> None:  # noqa: N802
        self.visit(node.subject)
        for index, case in enumerate(node.cases):
            self._push_branch(node, f"case-{index}")
            try:
                self.visit(case.pattern)
                if case.guard is not None:
                    self.visit(case.guard)
                for statement in case.body:
                    self.visit(statement)
            finally:
                self._pop_branch()

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        self.visit(node.test)
        self._visit_branch_suite(node, "body", node.body)
        self._visit_branch_suite(node, "else", node.orelse)

    def visit_Delete(self, node: ast.Delete) -> None:  # noqa: N802
        for target in node.targets:
            self._bind_target(target, position=node)

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self._visit_for(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:  # noqa: N802
        self._visit_for(node)

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        self._visit_with(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:  # noqa: N802
        self._visit_with(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        if node.name is not None:
            self._bind_other(node.name, position=node, at_start=True)
        if node.type is not None:
            self.visit(node.type)
        for statement in node.body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_definition_expressions(node)
        self._bind_other(node.name, position=node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_definition_expressions(node)
        self._bind_other(node.name, position=node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind_other(node.name, position=node)

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def visit_ListComp(self, node: ast.ListComp) -> None:  # noqa: N802
        del node

    def visit_SetComp(self, node: ast.SetComp) -> None:  # noqa: N802
        del node

    def visit_DictComp(self, node: ast.DictComp) -> None:  # noqa: N802
        del node

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:  # noqa: N802
        del node

    def visit_MatchAs(self, node: ast.MatchAs) -> None:  # noqa: N802
        if node.name is not None:
            self._bind_other(node.name, position=node)
        if node.pattern is not None:
            self.visit(node.pattern)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:  # noqa: N802
        if node.name is not None:
            self._bind_other(node.name, position=node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:  # noqa: N802
        if node.rest is not None:
            self._bind_other(node.rest, position=node)
        for pattern in node.patterns:
            self.visit(pattern)

    def visit_Global(self, node: ast.Global) -> None:  # noqa: N802
        self._external_declarations.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:  # noqa: N802
        self._external_declarations.update(node.names)

    def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._push_branch(node, "body")
        try:
            self._bind_target(node.target, position=node.iter)
            for statement in node.body:
                self.visit(statement)
        finally:
            self._pop_branch()
        self._visit_branch_suite(node, "else", node.orelse)

    def _visit_with(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars, position=item.context_expr)
        for statement in node.body:
            self.visit(statement)

    def _visit_definition_expressions(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        if node.returns is not None:
            self.visit(node.returns)

    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        self._push_branch(node, "body")
        try:
            for statement in node.body:
                self.visit(statement)
            self._push_branch(node, "else")
            try:
                for statement in node.orelse:
                    self.visit(statement)
            finally:
                self._pop_branch()
        finally:
            self._pop_branch()
        for index, handler in enumerate(node.handlers):
            self._visit_branch_node(node, f"handler-{index}", handler)
        for statement in node.finalbody:
            self.visit(statement)

    def _visit_branch_suite(
        self,
        control: ast.AST,
        label: str,
        suite: Iterable[ast.stmt],
    ) -> None:
        statements = tuple(suite)
        if not statements:
            return
        self._push_branch(control, label)
        try:
            for statement in statements:
                self.visit(statement)
        finally:
            self._pop_branch()

    def _visit_branch_node(
        self,
        control: ast.AST,
        label: str,
        node: ast.AST,
    ) -> None:
        self._push_branch(control, label)
        try:
            self.visit(node)
        finally:
            self._pop_branch()

    def _push_branch(self, control: ast.AST, label: str) -> None:
        self._branch_path.append(_branch_token(control, label))

    def _pop_branch(self) -> None:
        self._branch_path.pop()

    def _bind_exhaustive_safe_if_kills(self, node: ast.If) -> None:
        branch_tokens = (
            _branch_token(node, "body"),
            _branch_token(node, "else"),
        )
        branch_paths = tuple(
            (*self._branch_path, branch_token) for branch_token in branch_tokens
        )
        for name, bindings in tuple(self._bindings.items()):
            latest_by_branch = [
                _latest_binding_on_exact_path(bindings, branch_path)
                for branch_path in branch_paths
            ]
            if all(
                binding is not None and binding.canonical_name is None
                for binding in latest_by_branch
            ) and all(
                not _has_later_descendant_alias(
                    bindings,
                    branch_path=branch_path,
                    after=binding.position,
                )
                for branch_path, binding in zip(
                    branch_paths,
                    latest_by_branch,
                    strict=True,
                )
                if binding is not None
            ):
                self._bind(name, None, position=node)

    def _bind_alias(
        self,
        local_name: str,
        canonical_name: str,
        *,
        position: ast.AST,
    ) -> None:
        self._bind(local_name, canonical_name, position=position)

    def _bind_other(
        self,
        name: str,
        *,
        position: ast.AST,
        at_start: bool = False,
    ) -> None:
        self._bind(name, None, position=position, at_start=at_start)

    def _bind_target(self, target: ast.expr, *, position: ast.AST) -> None:
        for name in _target_names(target):
            self._bind(name, None, position=position)

    def _bind(
        self,
        name: str,
        canonical_name: str | None,
        *,
        position: ast.AST | None = None,
        always_active: bool = False,
        at_start: bool = False,
    ) -> None:
        if always_active:
            binding_position = (-1, -1, self._sequence)
        elif position is not None:
            if at_start:
                line, column = _node_start_position(position)[:2]
            else:
                line, column = _node_end_position(position)
            binding_position = (line, column, self._sequence)
        else:
            raise ValueError("binding position is required")
        self._sequence += 1
        self._bindings.setdefault(name, []).append(
            _NameBinding(
                position=binding_position,
                canonical_name=canonical_name,
                always_active=always_active,
                branch_path=tuple(self._branch_path),
            )
        )


def _collect_scope_bindings(
    kind: _ScopeKind,
    body: Iterable[ast.stmt],
    *,
    arguments: ast.arguments | None = None,
) -> _ScopeBindings:
    parameter_names = _argument_names(arguments) if arguments is not None else ()
    collector = _ScopeBindingCollector(parameter_names=parameter_names)
    for statement in body:
        collector.visit(statement)
    return collector.build(kind)


def _collect_lambda_scope_bindings(node: ast.Lambda) -> _ScopeBindings:
    collector = _ScopeBindingCollector(parameter_names=_argument_names(node.args))
    collector.visit(node.body)
    return collector.build("lambda")


def _always_shadowed_scope(
    kind: _ScopeKind,
    names: Iterable[str],
) -> _ScopeBindings:
    return _ScopeBindings(
        kind=kind,
        bindings={
            name: (
                _NameBinding(
                    position=(-1, -1, index),
                    canonical_name=None,
                    always_active=True,
                ),
            )
            for index, name in enumerate(names)
        },
    )


def _resolve_scope_binding_names(
    bindings: tuple[_NameBinding, ...],
    *,
    query_position: tuple[int, int, int],
    query_path: tuple[_BranchToken, ...],
) -> frozenset[str] | None:
    possible_names: set[str] = set()
    applicable = False
    for binding in bindings:
        if not binding.always_active and binding.position > query_position:
            continue
        relation = _binding_path_relation(
            binding.branch_path,
            query_path,
            query_position=query_position,
        )
        if relation == "ignore":
            continue
        applicable = True
        if relation == "must":
            possible_names.clear()
        if binding.canonical_name is not None:
            possible_names.add(binding.canonical_name)
    return frozenset(possible_names) if applicable else None


def _has_only_may_bindings(
    bindings: tuple[_NameBinding, ...],
    *,
    query_position: tuple[int, int, int],
    query_path: tuple[_BranchToken, ...],
) -> bool:
    applicable_relations = [
        _binding_path_relation(
            binding.branch_path,
            query_path,
            query_position=query_position,
        )
        for binding in bindings
        if binding.always_active or binding.position <= query_position
    ]
    visible_relations = [
        relation for relation in applicable_relations if relation != "ignore"
    ]
    return bool(visible_relations) and all(
        relation == "may" for relation in visible_relations
    )


def _latest_binding_on_exact_path(
    bindings: list[_NameBinding],
    branch_path: tuple[_BranchToken, ...],
) -> _NameBinding | None:
    matching = [
        binding for binding in bindings if binding.branch_path == branch_path
    ]
    return max(matching, key=lambda binding: binding.position, default=None)


def _has_later_descendant_alias(
    bindings: list[_NameBinding],
    *,
    branch_path: tuple[_BranchToken, ...],
    after: tuple[int, int, int],
) -> bool:
    return any(
        binding.position > after
        and binding.canonical_name is not None
        and len(binding.branch_path) > len(branch_path)
        and binding.branch_path[: len(branch_path)] == branch_path
        for binding in bindings
    )


def _binding_path_relation(
    binding_path: tuple[_BranchToken, ...],
    query_path: tuple[_BranchToken, ...],
    *,
    query_position: tuple[int, int, int],
) -> Literal["must", "may", "ignore"]:
    common_length = 0
    for binding_token, query_token in zip(binding_path, query_path, strict=False):
        if binding_token != query_token:
            break
        common_length += 1
    if common_length == len(binding_path):
        return "must"
    if common_length == len(query_path):
        return "may"

    binding_token = binding_path[common_length]
    query_token = query_path[common_length]
    if _same_branch_control(binding_token, query_token):
        if (
            binding_token.control_type in {"Try", "TryStar"}
            and binding_token.label == "body"
            and query_token.label.startswith("handler-")
        ):
            return "may"
        if binding_token.control_type in {"For", "AsyncFor", "While"}:
            return "may"
        return "ignore"
    if binding_token.control_end <= query_position[:2]:
        return "may"
    return "ignore"


def _same_branch_control(first: _BranchToken, second: _BranchToken) -> bool:
    return (
        first.control_type == second.control_type
        and first.control_start == second.control_start
        and first.control_end == second.control_end
    )


def _branch_token(control: ast.AST, label: str) -> _BranchToken:
    return _BranchToken(
        control_type=type(control).__name__,
        control_start=_node_start_position(control)[:2],
        control_end=_node_end_position(control),
        label=label,
    )


def _argument_names(arguments: ast.arguments) -> tuple[str, ...]:
    names = [
        argument.arg
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        )
    ]
    if arguments.vararg is not None:
        names.append(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.append(arguments.kwarg.arg)
    return tuple(names)


def _target_names(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in target.elts:
            names.update(_target_names(element))
        return names
    if isinstance(target, ast.Starred):
        return _target_names(target.value)
    return set()


def _preprocess_ipython(text: str) -> tuple[str, list[_Candidate]]:
    """Replace supported IPython-only syntax with spaces, preserving offsets.

    A finite Python string lexer tracks quoted regions across physical lines.
    Magic-looking lines inside strings are therefore left for :mod:`ast` instead
    of being interpreted as IPython syntax. Lines recognized as IPython are
    blanked without scanning their shell/magic arguments as Python source.
    """

    lines = text.splitlines(keepends=True)
    starts = _line_starts(text)
    transformed = list(text)
    candidates: list[_Candidate] = []
    first_code_line_seen = False
    string_delimiter: str | None = None

    for index, line in enumerate(lines):
        content = line.rstrip("\r\n")
        absolute = starts[index]
        if string_delimiter is not None:
            string_delimiter = _scan_python_string_state(content, string_delimiter)
            continue
        if not first_code_line_seen and not content.strip():
            continue
        cell_match = _IPYTHON_CELL_MAGIC.match(content)
        if not first_code_line_seen and cell_match is not None:
            first_code_line_seen = True
            start = absolute + cell_match.start()
            end = absolute + cell_match.end()
            candidates.append(_Candidate(start, end, "ipython_cell_magic", 1.0, 30))
            _blank_non_newline(transformed, absolute, absolute + len(line))
            if cell_match.group("name").lower() not in _PYTHON_BODY_CELL_MAGICS:
                for remaining_index in range(index + 1, len(lines)):
                    remaining_start = starts[remaining_index]
                    _blank_non_newline(
                        transformed,
                        remaining_start,
                        remaining_start + len(lines[remaining_index]),
                    )
                break
            continue
        first_code_line_seen = True

        shell_match = _IPYTHON_SHELL.match(content)
        if shell_match is not None:
            bang = absolute + shell_match.end() - 1
            end = absolute + len(content)
            candidates.append(
                _Candidate(
                    bang,
                    max(bang + 1, end),
                    "ipython_shell_escape",
                    0.99,
                    40,
                )
            )
            _replace_with_noop(
                transformed,
                start=absolute,
                end=absolute + len(line),
                content=content,
            )
            continue

        line_match = _IPYTHON_LINE_MAGIC.match(content)
        if line_match is not None:
            start = absolute + line_match.end("prefix")
            end = absolute + line_match.end()
            candidates.append(_Candidate(start, end, "ipython_line_magic", 1.0, 20))
            _replace_with_noop(
                transformed,
                start=absolute,
                end=absolute + len(line),
                content=content,
            )
            continue

        help_match = _IPYTHON_HELP.match(content)
        if help_match is not None:
            start = absolute + help_match.start("query")
            end = absolute + help_match.end("query")
            candidates.append(_Candidate(start, end, "ipython_help_query", 1.0, 10))
            _replace_with_noop(
                transformed,
                start=absolute,
                end=absolute + len(line),
                content=content,
            )
            continue

        string_delimiter = _scan_python_string_state(content, None)

    return "".join(transformed), candidates


def _syntax_error_candidate(text: str, error: SyntaxError) -> _Candidate:
    starts = _line_starts(text)
    line_number = error.lineno or 1
    line_index = min(max(line_number - 1, 0), max(len(starts) - 1, 0))
    line_start = starts[line_index]
    line_end = text.find("\n", line_start)
    if line_end < 0:
        line_end = len(text)
    column = max((error.offset or 1) - 1, 0)
    start = min(line_start + column, max(line_start, line_end - 1))
    end_column = max((error.end_offset or error.offset or 1) - 1, column + 1)
    end = min(line_start + end_column, line_end)
    if end <= start:
        end = min(len(text), start + 1)
    return _Candidate(start, end, "python_syntax_error", 1.0, 50)


def _detections_from_candidates(
    text: str,
    candidates: list[_Candidate],
    *,
    context: DetectionContext,
) -> list[Detection]:
    unique = {
        (candidate.start, candidate.end, candidate.type): candidate
        for candidate in candidates
        if 0 <= candidate.start < candidate.end <= len(text)
    }
    if len(unique) > MAX_PYTHON_AST_DETECTIONS:
        raise ValueError("Python AST detector result limit exceeded")
    ordered = sorted(
        unique.values(),
        key=lambda item: (item.start, -item.priority, item.end, item.type),
    )
    detections: list[Detection] = []
    for candidate in ordered:
        fingerprint = occurrence_fingerprint(
            context=context,
            detector=PythonASTIPythonDetector.name,
            detector_version=PythonASTIPythonDetector.version,
            detection_type=candidate.type,
            start=candidate.start,
            end=candidate.end,
        )
        detections.append(
            Detection(
                type=candidate.type,
                detector=PythonASTIPythonDetector.name,
                detector_version=PythonASTIPythonDetector.version,
                confidence=candidate.confidence,
                start=candidate.start,
                end=candidate.end,
                masked_evidence=(
                    f"<{PythonASTIPythonDetector.name}:{candidate.type}:{fingerprint}>"
                ),
                fingerprint=fingerprint,
            )
        )
    return detections


def _call_names(
    node: ast.expr,
    *,
    resolve_names: Callable[[str, ast.AST], frozenset[str]],
) -> frozenset[str]:
    if isinstance(node, ast.Name):
        return resolve_names(node.id, node)
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Call):
            parents = _call_names(node.value.func, resolve_names=resolve_names)
        else:
            parents = _call_names(node.value, resolve_names=resolve_names)
        return frozenset(f"{parent}.{node.attr}" for parent in parents if parent)
    return frozenset()


def _node_start_position(node: ast.AST) -> tuple[int, int, int]:
    return (
        getattr(node, "lineno", 0),
        getattr(node, "col_offset", 0),
        2**31 - 1,
    )


def _node_end_position(node: ast.AST) -> tuple[int, int]:
    return (
        getattr(node, "end_lineno", getattr(node, "lineno", 0)),
        getattr(node, "end_col_offset", getattr(node, "col_offset", 0)),
    )


def _is_builtin_name(name: str) -> bool:
    if name in _BUILTIN_NAMES:
        return True
    root, separator, member = name.partition(".")
    return root == "builtins" and separator == "." and member in _BUILTIN_NAMES


def _scan_python_string_state(content: str, delimiter: str | None) -> str | None:
    """Return the quote delimiter still open after one physical source line."""

    index = 0
    while index < len(content):
        if delimiter is not None:
            closing = content.find(delimiter, index)
            while closing >= 0 and _is_escaped(content, closing):
                closing = content.find(delimiter, closing + 1)
            if closing < 0:
                if len(delimiter) == 1 and not _has_escaped_line_ending(content):
                    return None
                return delimiter
            index = closing + len(delimiter)
            delimiter = None
            continue

        character = content[index]
        if character == "#":
            return None
        if character not in {"'", '"'}:
            index += 1
            continue
        triple = character * 3
        delimiter = triple if content.startswith(triple, index) else character
        index += len(delimiter)

    if delimiter is not None and len(delimiter) == 1:
        return delimiter if _has_escaped_line_ending(content) else None
    return delimiter


def _is_escaped(content: str, index: int) -> bool:
    backslashes = 0
    index -= 1
    while index >= 0 and content[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _has_escaped_line_ending(content: str) -> bool:
    backslashes = 0
    index = len(content) - 1
    while index >= 0 and content[index] == "\\":
        backslashes += 1
        index -= 1
    return backslashes % 2 == 1


def _module_root(module: str) -> str:
    return module.split(".", 1)[0]


def _line_starts(text: str) -> list[int]:
    starts = [0]
    starts.extend(index + 1 for index, character in enumerate(text) if character == "\n")
    return starts


def _ast_offset(
    lines: list[str],
    starts: list[int],
    line_number: int,
    byte_column: int,
) -> int:
    line_index = line_number - 1
    line = lines[line_index]
    prefix = line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore")
    return starts[line_index] + len(prefix)


def _blank_non_newline(characters: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if characters[index] not in {"\r", "\n"}:
            characters[index] = " "


def _replace_with_noop(
    characters: list[str],
    *,
    start: int,
    end: int,
    content: str,
) -> None:
    """Replace one IPython line with an equal-length valid Python statement."""

    _blank_non_newline(characters, start, end)
    indent_length = len(content) - len(content.lstrip(" \t"))
    statement_length = len(content) - indent_length
    noop = "pass" if statement_length >= len("pass") else "0"
    insertion = start + indent_length
    characters[insertion : insertion + len(noop)] = noop
