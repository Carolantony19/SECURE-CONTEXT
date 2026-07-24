"""Unit tests for secretguard.taint.sinks."""

from __future__ import annotations

import ast
from secretguard.taint.sinks import identify_sink


class TestSinks:
    def test_identify_print_sink(self) -> None:
        tree = ast.parse("print(secret_key)")
        call_node = tree.body[0].value  # type: ignore
        sink = identify_sink(call_node)
        assert sink is not None
        assert sink.category == "PRINT"
        assert sink.sink_name == "print()"

    def test_identify_logging_sink(self) -> None:
        tree = ast.parse("logger.info('Token is %s', secret_key)")
        call_node = tree.body[0].value  # type: ignore
        sink = identify_sink(call_node)
        assert sink is not None
        assert sink.category == "LOGGING"
        assert "logger.info" in sink.sink_name

    def test_identify_file_write_sink(self) -> None:
        tree = ast.parse("f.write(secret_key)")
        call_node = tree.body[0].value  # type: ignore
        sink = identify_sink(call_node)
        assert sink is not None
        assert sink.category == "FILE_WRITE"

    def test_identify_network_sink(self) -> None:
        tree = ast.parse("requests.post('https://api.example.com', json={'key': secret_key})")
        call_node = tree.body[0].value  # type: ignore
        sink = identify_sink(call_node)
        assert sink is not None
        assert sink.category == "NETWORK"
        assert "requests.post" in sink.sink_name

    def test_non_sink_call(self) -> None:
        tree = ast.parse("calculate_sum(a, b)")
        call_node = tree.body[0].value  # type: ignore
        sink = identify_sink(call_node)
        assert sink is None
