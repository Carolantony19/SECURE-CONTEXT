"""
AST parser and statement extractor for SecretGuard AI taint analysis.

Parses Python source files into Python `ast` AST trees, extracting:
- Assignments (simple: `x = y`, tuple unpack: `a, b = x, y`, annotated: `x: str = y`)
- Function & Method Definitions (`def foo(a, b): ...`)
- Function & Method Calls (`foo(a)`, `obj.method(b)`)
- Imports (`import mod`, `from mod import var as alias`)
- String Formats (f-strings `f"{var}"`, `.format()`, `%`)
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class AssignmentNode:
    """Extracted assignment statement from AST."""
    target_vars: list[str]
    source_vars: list[str]
    line_number: int
    is_string_formatting: bool = False
    format_components: list[str] = field(default_factory=list)


@dataclass
class ImportNode:
    """Extracted import statement from AST."""
    module_name: str
    imported_name: str  # symbol or '*' or module name
    alias: str          # local binding name
    line_number: int
    is_from_import: bool = False


@dataclass
class FunctionDefNode:
    """Extracted function definition statement from AST."""
    name: str
    parameters: list[str]
    line_number: int
    ast_node: ast.FunctionDef


@dataclass
class CallSiteNode:
    """Extracted function call site statement from AST."""
    func_name: str
    positional_args: list[str]  # variable names passed
    keyword_args: dict[str, str] # {kwarg_name: variable_name}
    line_number: int
    ast_node: ast.Call


@dataclass
class ParsedASTFile:
    """Container for all extracted elements from a single Python file."""
    filepath: Path
    ast_tree: ast.AST
    assignments: list[AssignmentNode] = field(default_factory=list)
    imports: list[ImportNode] = field(default_factory=list)
    function_defs: list[FunctionDefNode] = field(default_factory=list)
    call_sites: list[CallSiteNode] = field(default_factory=list)


def _extract_var_names(node: ast.AST) -> list[str]:
    """Extract variable names from an AST expression."""
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Attribute):
        base = _extract_var_names(node.value)
        if base:
            names.append(f"{base[0]}.{node.attr}")
        names.append(node.attr)
    elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for elt in node.elts:
            names.extend(_extract_var_names(elt))
    elif isinstance(node, ast.Dict):
        for key in node.keys:
            if key:
                names.extend(_extract_var_names(key))
        for val in node.values:
            names.extend(_extract_var_names(val))
    elif isinstance(node, ast.FormattedValue):
        names.extend(_extract_var_names(node.value))
    elif isinstance(node, ast.JoinedStr):  # f-string
        for value in node.values:
            names.extend(_extract_var_names(value))
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):  # % format
        names.extend(_extract_var_names(node.left))
        names.extend(_extract_var_names(node.right))
    elif isinstance(node, ast.Call):
        # Extract names from args & keywords
        for arg in node.args:
            names.extend(_extract_var_names(arg))
        for kw in node.keywords:
            names.extend(_extract_var_names(kw.value))
    return names



class _ASTVisitor(ast.NodeVisitor):
    """Visitor that extracts assignments, imports, function defs, and calls."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.assignments: list[AssignmentNode] = []
        self.imports: list[ImportNode] = []
        self.function_defs: list[FunctionDefNode] = []
        self.call_sites: list[CallSiteNode] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        targets: list[str] = []
        for t in node.targets:
            targets.extend(_extract_var_names(t))

        sources = _extract_var_names(node.value)
        is_fmt = isinstance(node.value, (ast.JoinedStr, ast.FormattedValue))

        self.assignments.append(AssignmentNode(
            target_vars=targets,
            source_vars=sources,
            line_number=node.lineno,
            is_string_formatting=is_fmt,
            format_components=sources if is_fmt else [],
        ))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            targets = _extract_var_names(node.target)
            sources = _extract_var_names(node.value)
            is_fmt = isinstance(node.value, (ast.JoinedStr, ast.FormattedValue))
            self.assignments.append(AssignmentNode(
                target_vars=targets,
                source_vars=sources,
                line_number=node.lineno,
                is_string_formatting=is_fmt,
                format_components=sources if is_fmt else [],
            ))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.imports.append(ImportNode(
                module_name=alias.name,
                imported_name=alias.name,
                alias=local_name,
                line_number=node.lineno,
                is_from_import=False,
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod_name = node.module or ""
        for alias in node.names:
            local_name = alias.asname or alias.name
            self.imports.append(ImportNode(
                module_name=mod_name,
                imported_name=alias.name,
                alias=local_name,
                line_number=node.lineno,
                is_from_import=True,
            ))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        params = [arg.arg for arg in node.args.args]
        self.function_defs.append(FunctionDefNode(
            name=node.name,
            parameters=params,
            line_number=node.lineno,
            ast_node=node,
        ))
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        params = [arg.arg for arg in node.args.args]
        self.function_defs.append(FunctionDefNode(
            name=node.name,
            parameters=params,
            line_number=node.lineno,
            ast_node=node,  # type: ignore[arg-type]
        ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            base = _extract_var_names(node.func.value)
            func_name = f"{base[0]}.{node.func.attr}" if base else node.func.attr

        pos_args: list[str] = []
        for arg in node.args:
            extracted = _extract_var_names(arg)
            pos_args.extend(extracted)

        kw_args: dict[str, str] = {}
        for kw in node.keywords:
            if kw.arg:
                extracted = _extract_var_names(kw.value)
                for vname in extracted:
                    kw_args[vname] = vname
                if extracted:
                    kw_args[kw.arg] = extracted[0]


        self.call_sites.append(CallSiteNode(
            func_name=func_name,
            positional_args=pos_args,
            keyword_args=kw_args,
            line_number=node.lineno,
            ast_node=node,
        ))
        self.generic_visit(node)


def parse_python_file(filepath: Path) -> Optional[ParsedASTFile]:
    """Parse a Python source file into a ParsedASTFile data container."""
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
    except (OSError, SyntaxError, UnicodeError):
        return None

    visitor = _ASTVisitor(filepath)
    visitor.visit(tree)

    return ParsedASTFile(
        filepath=filepath,
        ast_tree=tree,
        assignments=visitor.assignments,
        imports=visitor.imports,
        function_defs=visitor.function_defs,
        call_sites=visitor.call_sites,
    )
