
"""Unit tests for secretguard.taint.call_graph."""

from __future__ import annotations

from pathlib import Path
from secretguard.taint.ast_parser import parse_python_file
from secretguard.taint.call_graph import CallGraph


class TestCallGraph:
    def test_build_call_graph_same_file(self, tmp_path: Path) -> None:
        f = tmp_path / "main.py"
        f.write_text(
            'def connect(key):\n'
            '    print(key)\n'
            '\n'
            'secret = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"\n'
            'connect(secret)\n',
            encoding="utf-8",
        )

        parsed = parse_python_file(f)
        assert parsed is not None

        cg = CallGraph()
        cg.build([parsed])

        assert len(cg.edges) == 1
        edge = cg.edges[0]
        assert edge.target_function.name == "connect"
        assert edge.arg_to_param_map.get("secret") == "key"
