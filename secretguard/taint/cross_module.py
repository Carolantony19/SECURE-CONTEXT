"""
Cross-module import resolver for SecretGuard AI taint analysis.

Resolves imports across project Python files (e.g. `from config import API_KEY`,
`from utils import connect as conn`, or `import config`) to map cross-file
taint propagation links.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secretguard.taint.ast_parser import ImportNode, ParsedASTFile


@dataclass
class ImportLink:
    """Represents a resolved import link between source and target files."""

    source_filepath: Path  # File containing the import statement
    target_filepath: Path  # Resolved imported file on disk
    imported_symbol: str   # Imported symbol name (variable or function)
    local_alias: str       # Local variable name in source file
    line_number: int


class ModuleResolver:
    """Resolves Python module import statements to actual files on disk."""

    def __init__(self, repo_root: Path, parsed_files: list[ParsedASTFile]):
        self.repo_root = repo_root.resolve()
        self.parsed_files = {p.filepath.resolve(): p for p in parsed_files}
        self.module_map: dict[str, Path] = {}
        self._build_module_map()

    def _build_module_map(self) -> None:
        """Map Python module dot-notation (e.g. 'config', 'pkg.submod') to file paths."""
        for filepath in self.parsed_files.keys():
            try:
                rel = filepath.resolve().relative_to(self.repo_root)
            except ValueError:
                # Fallback: match by filename stem if outside repo_root
                rel = Path(filepath.name)


            # Convert path to module string: 'foo/bar.py' -> 'foo.bar'
            parts = list(rel.parts)
            if parts[-1].endswith(".py"):
                parts[-1] = parts[-1][:-3]
            if parts[-1] == "__init__":
                parts.pop()

            mod_str = ".".join(parts)
            if mod_str:
                self.module_map[mod_str] = filepath

    def resolve_import(
        self, source_file: Path, import_node: ImportNode
    ) -> Optional[ImportLink]:
        """Attempt to resolve an ImportNode from *source_file* to a target file on disk."""
        target_path: Optional[Path] = None

        # 1. Direct module lookup
        if import_node.module_name in self.module_map:
            target_path = self.module_map[import_node.module_name]

        # 2. Relative / sub-module fallback
        if not target_path:
            for mod_str, path in self.module_map.items():
                if mod_str.endswith(import_node.module_name):
                    target_path = path
                    break

        if not target_path or not target_path.exists():
            return None

        return ImportLink(
            source_filepath=source_file,
            target_filepath=target_path,
            imported_symbol=import_node.imported_name,
            local_alias=import_node.alias,
            line_number=import_node.line_number,
        )

    def resolve_all_links(self) -> list[ImportLink]:
        """Resolve all import links across all parsed files in the repository."""
        links: list[ImportLink] = []
        for parsed in self.parsed_files.values():
            for imp in parsed.imports:
                link = self.resolve_import(parsed.filepath, imp)
                if link:
                    links.append(link)
        return links
