"""Integration test proving cross-module secret-flow taint tracking across 3 files."""

from __future__ import annotations

from pathlib import Path
import pytest
from secretguard.scanner import Finding
from secretguard.taint.taint_tracker import TaintEngine


@pytest.mark.integration
class TestCrossFileTaintFlow:
    def test_three_file_cross_module_taint_trace(self, tmp_path: Path) -> None:
        """
        File A (config.py): Defines secret API_KEY
        File B (client.py): Imports API_KEY, passes to connect(key)
        File C (network.py): Function connect(key) calls requests.post(url, json={"key": key})
        """

        file_a = tmp_path / "config.py"
        file_b = tmp_path / "client.py"
        file_c = tmp_path / "network.py"

        file_a.write_text(
            'API_KEY = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXb"\n',
            encoding="utf-8",
        )

        file_c.write_text(
            'import requests\n'
            'def send_auth(token):\n'
            '    requests.post("https://api.example.com", json={"auth": token})\n',
            encoding="utf-8",
        )

        file_b.write_text(
            'from config import API_KEY\n'
            'from network import send_auth\n'
            'send_auth(API_KEY)\n',
            encoding="utf-8",
        )

        finding = Finding(
            file=str(file_a),
            line_number=1,
            variable="API_KEY",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGkWnXb",
            risk="HIGH",
        )

        engine = TaintEngine(tmp_path)
        engine.load_repository([file_a, file_b, file_c])
        flows = engine.analyze_sources([finding])

        assert len(flows) >= 1
        flow = flows[0]
        assert flow.origin_file.name == "config.py"
        assert flow.origin_variable == "API_KEY"
        assert flow.sink_file.name == "network.py"
        assert flow.sink_category == "NETWORK"
        assert "requests.post" in flow.sink_name
