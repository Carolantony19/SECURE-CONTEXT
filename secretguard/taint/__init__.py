"""
SecretGuard AI — Interprocedural Taint & Secret-Flow Analysis Engine.

Tracks how detected secret values propagate across variable reassignments,
function call arguments, and module imports into dangerous sinks (print, logging,
file writes, network requests, URL/header formatting).
"""

__all__ = [
    "sinks",
    "ast_parser",
    "call_graph",
    "cross_module",
    "taint_tracker",
    "llm_disambiguator",
    "report",
]
