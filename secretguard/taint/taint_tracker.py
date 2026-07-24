"""
Core intraprocedural and interprocedural taint tracking engine for SecretGuard AI.

Takes taint sources (findings from scanner/entropy flagged as secrets) and tracks
their propagation across:
1. Reassignments (`new_var = secret_var`)
2. String interpolations (`f"token={secret_var}"`, `.format()`, `%`)
3. Function arguments (`connect(secret_var)` -> parameter `key` in `def connect(key):`)
4. Module imports (`from config import API_KEY`)

When a tainted variable reaches a dangerous sink (print, logging, file write, network request),
records a complete TaintFlow path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secretguard.scanner import Finding
from secretguard.taint.ast_parser import ParsedASTFile, parse_python_file
from secretguard.taint.call_graph import CallGraph
from secretguard.taint.cross_module import ModuleResolver
from secretguard.taint.sinks import SinkMatch, identify_sink


@dataclass
class FlowStep:
    """A single step in a secret's propagation path."""
    file: Path
    line_number: int
    expression: str
    detail: str


@dataclass
class TaintFlow:
    """A complete secret propagation path from origin definition to dangerous sink."""
    origin_file: Path
    origin_line: int
    origin_variable: str
    raw_secret_value: str
    sink_file: Path
    sink_line: int
    sink_name: str
    sink_category: str
    sink_description: str
    steps: list[FlowStep] = field(default_factory=list)


class TaintEngine:
    """Engine that performs static intraprocedural and interprocedural taint analysis."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.parsed_files: dict[Path, ParsedASTFile] = {}
        self.call_graph = CallGraph()
        self.resolver: Optional[ModuleResolver] = None
        self.flows: list[TaintFlow] = []

    def load_repository(self, python_files: list[Path]) -> None:
        """Parse all Python files and build module maps and call graphs."""
        parsed_list: list[ParsedASTFile] = []
        for fp in python_files:
            parsed = parse_python_file(fp)
            if parsed:
                self.parsed_files[fp.resolve()] = parsed
                parsed_list.append(parsed)

        self.resolver = ModuleResolver(self.repo_root, parsed_list)
        self.call_graph.build(parsed_list, self.resolver)

    def analyze_sources(self, initial_findings: list[Finding]) -> list[TaintFlow]:
        """Track taint propagation from initial secret findings to dangerous sinks."""
        self.flows.clear()

        # Group findings by file
        for finding in initial_findings:
            # Skip placeholders or non-secrets
            if finding.risk in ("LOW", "SUPPRESSED") or finding.is_placeholder:
                continue

            origin_file = Path(finding.file).resolve()
            parsed = self.parsed_files.get(origin_file)
            if not parsed:
                # Try parsing if not loaded yet
                parsed = parse_python_file(origin_file)
                if parsed:
                    self.parsed_files[origin_file] = parsed

            if not parsed:
                continue

            # Start taint tracking for this finding
            self._track_variable_taint(
                origin_file=origin_file,
                origin_line=finding.line_number,
                var_name=finding.variable,
                raw_value=finding.raw_value,
                current_file=origin_file,
                current_var=finding.variable,
                current_line=finding.line_number,
                steps=[
                    FlowStep(
                        file=origin_file,
                        line_number=finding.line_number,
                        expression=f'{finding.variable} = "{finding.masked_value or finding.raw_value[:6]}***"',
                        detail=f"Secret defined in {origin_file.name}",
                    )
                ],
                visited=set(),
            )

        return self.flows

    def _track_variable_taint(
        self,
        origin_file: Path,
        origin_line: int,
        var_name: str,
        raw_value: str,
        current_file: Path,
        current_var: str,
        current_line: int,
        steps: list[FlowStep],
        visited: set[tuple[str, str, int]],  # (file_str, var_str, line)
    ) -> None:
        visit_key = (str(current_file), current_var, current_line)
        if visit_key in visited:
            return
        visited.add(visit_key)

        parsed = self.parsed_files.get(current_file.resolve())
        if not parsed:
            return

        # 1. Intraprocedural: Check assignments in current file
        for assign in parsed.assignments:
            if assign.line_number < current_line:
                continue

            # If current_var is in source_vars, then target_vars become tainted!
            if current_var in assign.source_vars:
                for target_var in assign.target_vars:
                    next_steps = list(steps) + [
                        FlowStep(
                            file=current_file,
                            line_number=assign.line_number,
                            expression=f"{target_var} = {current_var}",
                            detail=f"Reassigned to variable '{target_var}'",
                        )
                    ]
                    self._track_variable_taint(
                        origin_file=origin_file,
                        origin_line=origin_line,
                        var_name=var_name,
                        raw_value=raw_value,
                        current_file=current_file,
                        current_var=target_var,
                        current_line=assign.line_number,
                        steps=next_steps,
                        visited=visited.copy(),
                    )

        # 2. Check function calls & Sinks in current file
        for call_site in parsed.call_sites:
            if call_site.line_number < current_line:
                continue

            # Is this call site a dangerous sink?
            sink_match = identify_sink(call_site.ast_node)
            is_tainted_arg = False

            for arg_var in call_site.positional_args:
                if arg_var == current_var:
                    is_tainted_arg = True
                    break
            for kw_val in call_site.keyword_args.values():
                if kw_val == current_var:
                    is_tainted_arg = True
                    break

            if is_tainted_arg and sink_match:
                # Flow reached a sink!
                final_steps = list(steps) + [
                    FlowStep(
                        file=current_file,
                        line_number=call_site.line_number,
                        expression=f"{call_site.func_name}(...{current_var}...)",
                        detail=f"Reached sink '{sink_match.sink_name}' ({sink_match.description})",
                    )
                ]
                self.flows.append(TaintFlow(
                    origin_file=origin_file,
                    origin_line=origin_line,
                    origin_variable=var_name,
                    raw_secret_value=raw_value,
                    sink_file=current_file,
                    sink_line=call_site.line_number,
                    sink_name=sink_match.sink_name,
                    sink_category=sink_match.category,
                    sink_description=sink_match.description,
                    steps=final_steps,
                ))

            # 3. Interprocedural: Propagate taint into callee function parameter!
            if is_tainted_arg:
                for edge in self.call_graph.edges:
                    if (
                        edge.caller_file.resolve() == current_file.resolve()
                        and edge.call_site.line_number == call_site.line_number
                    ):
                        # Find corresponding parameter name
                        target_param = edge.arg_to_param_map.get(current_var)
                        if target_param:
                            next_steps = list(steps) + [
                                FlowStep(
                                    file=edge.callee_file,
                                    line_number=edge.target_function.line_number,
                                    expression=f"def {edge.target_function.name}({target_param}, ...)",
                                    detail=f"Passed into function '{edge.target_function.name}' as parameter '{target_param}'",
                                )
                            ]
                            self._track_variable_taint(
                                origin_file=origin_file,
                                origin_line=origin_line,
                                var_name=var_name,
                                raw_value=raw_value,
                                current_file=edge.callee_file,
                                current_var=target_param,
                                current_line=edge.target_function.line_number,
                                steps=next_steps,
                                visited=visited.copy(),
                            )

        # 4. Cross-Module: Propagate taint across imports!
        if self.resolver:
            for link in self.resolver.resolve_all_links():
                if (
                    link.target_filepath.resolve() == current_file.resolve()
                    and link.imported_symbol == current_var
                ):
                    next_steps = list(steps) + [
                        FlowStep(
                            file=link.source_filepath,
                            line_number=link.line_number,
                            expression=f"from {current_file.stem} import {current_var}",
                            detail=f"Imported by {link.source_filepath.name} as '{link.local_alias}'",
                        )
                    ]
                    self._track_variable_taint(
                        origin_file=origin_file,
                        origin_line=origin_line,
                        var_name=var_name,
                        raw_value=raw_value,
                        current_file=link.source_filepath,
                        current_var=link.local_alias,
                        current_line=link.line_number,
                        steps=next_steps,
                        visited=visited.copy(),
                    )
