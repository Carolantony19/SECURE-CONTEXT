"""Unit tests for secretguard.taint.taint_tracker."""

from __future__ import annotations

from pathlib import Path
from secretguard.scanner import Finding
from secretguard.taint.taint_tracker import TaintEngine


class TestTaintTracker:
    def test_single_file_reassignment_and_sink(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text(
            'api_key = "aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s"\n'
            'token = api_key\n'
            'print(token)\n',
            encoding="utf-8",
        )

        finding = Finding(
            file=str(f),
            line_number=1,
            variable="api_key",
            raw_value="aB3xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0s",
            risk="HIGH",
        )

        engine = TaintEngine(tmp_path)
        engine.load_repository([f])
        flows = engine.analyze_sources([finding])

        assert len(flows) >= 1
        flow = flows[0]
        assert flow.origin_variable == "api_key"
        assert flow.sink_name == "print()"
        assert flow.sink_category == "PRINT"

    def test_interprocedural_argument_propagation(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text(
            'def log_data(data):\n'
            '    logger.info("Log: %s", data)\n'
            '\n'
            'db_password = "xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGk"\n'
            'log_data(db_password)\n',
            encoding="utf-8",
        )

        finding = Finding(
            file=str(f),
            line_number=4,
            variable="db_password",
            raw_value="xK9mNpQ7rT2wU5yZ8cE1fH4jL6oI0sVdGk",
            risk="HIGH",
        )

        engine = TaintEngine(tmp_path)
        engine.load_repository([f])
        flows = engine.analyze_sources([finding])

        assert len(flows) >= 1
        flow = flows[0]
        assert flow.sink_category == "LOGGING"
