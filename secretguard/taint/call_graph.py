"""
Call graph builder for SecretGuard AI interprocedural taint analysis.

Builds per-file and cross-file Call Graphs linking function calls (`foo(secret)`)
to target function definitions (`def foo(arg): ...`), mapping argument positions
and keywords to parameter names.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secretguard.taint.ast_parser import CallSiteNode, FunctionDefNode, ParsedASTFile
from secretguard.taint.cross_module import ModuleResolver


@dataclass
class CallEdge:
    """Represents a call edge from a call site to a function definition."""

    caller_file: Path
    call_site: CallSiteNode
    callee_file: Path
    target_function: FunctionDefNode
    arg_to_param_map: dict[str, str] = field(default_factory=dict)
    # maps {passed_variable_name: target_parameter_name}


class CallGraph:
    """Represents a global call graph across files in the project."""

    def __init__(self):
        self.edges: list[CallEdge] = []
        self.functions_by_name: dict[str, list[tuple[Path, FunctionDefNode]]] = {}

    def register_function(self, filepath: Path, func_def: FunctionDefNode) -> None:
        """Register a function definition in the call graph."""
        self.functions_by_name.setdefault(func_def.name, []).append((filepath, func_def))

    def build(
        self, parsed_files: list[ParsedASTFile], resolver: Optional[ModuleResolver] = None
    ) -> None:
        """Build call graph edges from parsed files and resolved import links."""
        # 1. Register all functions
        for parsed in parsed_files:
            for func_def in parsed.function_defs:
                self.register_function(parsed.filepath, func_def)

        # 2. Map call sites to functions
        for parsed in parsed_files:
            for call in parsed.call_sites:
                target_name = call.func_name.split(".")[-1]
                candidates = self.functions_by_name.get(target_name, [])
                if not candidates:
                    continue

                # Match candidate function (prefer same file first, then imported)
                target_file, target_def = candidates[0]
                for c_file, c_def in candidates:
                    if c_file == parsed.filepath:
                        target_file, target_def = c_file, c_def
                        break

                # Map positional args to param names
                arg_map: dict[str, str] = {}
                for idx, arg_var in enumerate(call.positional_args):
                    if idx < len(target_def.parameters) and arg_var:
                        param_name = target_def.parameters[idx]
                        arg_map[arg_var] = param_name

                # Map keyword args to param names
                for kw_name, arg_var in call.keyword_args.items():
                    if kw_name in target_def.parameters and arg_var:
                        arg_map[arg_var] = kw_name

                self.edges.append(CallEdge(
                    caller_file=parsed.filepath,
                    call_site=call,
                    callee_file=target_file,
                    target_function=target_def,
                    arg_to_param_map=arg_map,
                ))
