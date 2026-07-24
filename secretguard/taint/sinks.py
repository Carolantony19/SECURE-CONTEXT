"""
Dangerous sink definitions for SecretGuard AI taint analysis.

Categories of sinks:
- PRINT: print()
- LOGGING: logging.info, logger.debug, etc.
- FILE_WRITE: open().write(), json.dump, Path.write_text, etc.
- NETWORK: requests.get/post, httpx, urllib, socket sends
- URL_HEADER_FORMAT: string formatting into headers or URL structures
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Optional


@dataclass
class SinkMatch:
    """Represents a matched sink call in AST."""

    category: str  # PRINT | LOGGING | FILE_WRITE | NETWORK | URL_HEADER_FORMAT
    sink_name: str
    line_number: int
    arg_indices: list[int]
    kwarg_names: list[str]
    description: str


_LOGGING_NAMES = {
    "info", "debug", "warning", "warn", "error", "critical", "exception", "log"
}

_NETWORK_FUNCS = {
    "get", "post", "put", "delete", "patch", "head", "options", "request",
    "urlopen", "send", "sendall", "sendto"
}

_NETWORK_MODULES = {"requests", "httpx", "urllib", "aiohttp", "socket"}

_FILE_WRITE_FUNCS = {
    "write", "writelines", "dump", "dumps", "write_text", "write_bytes"
}


def _get_call_name(node: ast.AST) -> str:
    """Extract full string representation of a call func name."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base = _get_call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def identify_sink(node: ast.Call) -> Optional[SinkMatch]:
    """Inspect an AST Call node and return SinkMatch if it matches a dangerous sink."""
    func_name = _get_call_name(node.func)
    line = getattr(node, "lineno", 0)

    # 1. PRINT sink
    if func_name == "print":
        return SinkMatch(
            category="PRINT",
            sink_name="print()",
            line_number=line,
            arg_indices=list(range(len(node.args))),
            kwarg_names=[],
            description="Console print statement",
        )

    # 2. LOGGING sink
    parts = func_name.split(".")
    if (
        len(parts) >= 2
        and parts[-1] in _LOGGING_NAMES
        and parts[0] in ("logging", "logger", "log", "self")
    ) or (len(parts) == 1 and parts[0] in ("logging", "logger", "log")):
        return SinkMatch(
            category="LOGGING",
            sink_name=func_name,
            line_number=line,
            arg_indices=list(range(len(node.args))),
            kwarg_names=[kw.arg for kw in node.keywords if kw.arg],
            description="Logger output call",
        )

    # 3. FILE_WRITE sink
    if parts[-1] in _FILE_WRITE_FUNCS:
        # e.g., f.write(secret), json.dump(secret, f), Path.write_text(secret)
        return SinkMatch(
            category="FILE_WRITE",
            sink_name=func_name,
            line_number=line,
            arg_indices=list(range(len(node.args))),
            kwarg_names=[kw.arg for kw in node.keywords if kw.arg],
            description="File write operation",
        )

    # 4. NETWORK sink
    if (
        len(parts) >= 2
        and parts[0] in _NETWORK_MODULES
        and parts[-1] in _NETWORK_FUNCS
    ) or (func_name in ("urlopen", "send", "sendall")):
        return SinkMatch(
            category="NETWORK",
            sink_name=func_name,
            line_number=line,
            arg_indices=list(range(len(node.args))),
            kwarg_names=[kw.arg for kw in node.keywords if kw.arg],
            description="Outgoing network call",
        )

    # 5. URL / Header formatting sink (e.g. Header(Authorization=secret))
    if func_name.lower() in ("header", "headers", "set_header", "add_header", "authorization"):
        return SinkMatch(
            category="URL_HEADER_FORMAT",
            sink_name=func_name,
            line_number=line,
            arg_indices=list(range(len(node.args))),
            kwarg_names=[kw.arg for kw in node.keywords if kw.arg],
            description="Header or URL credential formatting",
        )

    return None
