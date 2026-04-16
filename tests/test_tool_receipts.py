"""Tests for tool call receipts (Module 2)."""

from __future__ import annotations

import json

import pytest

from traceseal_observe import (
    OperatorKey,
    Receipt,
    ToolCallRecord,
    observe_http_tool,
    observe_mcp_tool,
    observe_shell_tool,
    observe_tool,
    observe_tool_fn,
    sign_tool_call,
)


@pytest.fixture
def key():
    return OperatorKey.generate("test-operator")


class TestSignToolCall:
    def test_produces_valid_receipt(self, key):
        record = ToolCallRecord(
            tool_name="search_web",
            transport="python",
            input_hash="sha256:abc",
            output_hash="sha256:def",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=150,
            ok=True,
        )
        receipt = sign_tool_call(record, key)
        assert receipt.receipt_version == "1.0"
        assert receipt.execution["receipt_type"] == "tool"
        assert receipt.execution["tool_name"] == "search_web"
        assert receipt.execution["transport"] == "python"
        assert receipt.execution["ok"] == "true"
        assert len(receipt.attestation["signature"]) == 128

    def test_records_optional_fields_when_present(self, key):
        record = ToolCallRecord(
            tool_name="send_email",
            transport="http",
            input_hash="sha256:xyz",
            output_hash="sha256:fgh",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=200,
            ok=True,
            tool_version="2.1.0",
            endpoint="https://api.mailgun.com/v3/send",
        )
        receipt = sign_tool_call(record, key)
        assert receipt.execution["tool_version"] == "2.1.0"
        assert receipt.execution["endpoint"] == "https://api.mailgun.com/v3/send"

    def test_omits_optional_fields_when_empty(self, key):
        record = ToolCallRecord(
            tool_name="search_web",
            transport="python",
            input_hash="sha256:abc",
            output_hash="sha256:def",
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=150,
            ok=True,
        )
        receipt = sign_tool_call(record, key)
        # Don't include empty strings for optional fields
        assert "tool_version" not in receipt.execution
        assert "endpoint" not in receipt.execution


class TestObserveTool:
    def test_wraps_python_function(self, key):
        def my_function(x: int) -> int:
            return x * 2

        result, receipt = observe_tool(
            tool_name="double",
            operator_key=key,
            call=lambda: my_function(5),
            args={"x": 5},
        )
        assert result == 10
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["tool_name"] == "double"

    def test_failed_call_still_produces_receipt(self, key):
        def failing():
            raise ValueError("bad input")

        result, receipt = observe_tool(
            tool_name="failer",
            operator_key=key,
            call=failing,
            args={"input": "bad"},
        )
        assert result is None
        assert receipt.execution["ok"] == "false"
        assert "bad input" in receipt.execution["error_message"]

    def test_timing_recorded(self, key):
        import time as _time

        def slow():
            _time.sleep(0.05)
            return "done"

        result, receipt = observe_tool(
            tool_name="slow_tool",
            operator_key=key,
            call=slow,
        )
        assert result == "done"
        # Wall time should be at least 50ms
        assert receipt.execution["wall_time_ms"] >= 40

    def test_empty_args_produces_empty_hash(self, key):
        result, receipt = observe_tool(
            tool_name="no_args",
            operator_key=key,
            call=lambda: {"result": 42},
        )
        assert receipt.execution["input_hash"] == "sha256:empty"

    def test_none_result_handled(self, key):
        result, receipt = observe_tool(
            tool_name="returns_none",
            operator_key=key,
            call=lambda: None,
        )
        assert result is None
        assert receipt.execution["ok"] == "true"


class TestObserveToolFnDecorator:
    def test_tuple_return_mode(self, key):
        @observe_tool_fn(operator_key=key, tool_name="my_search")
        def search(query: str) -> list:
            return [{"result": query}]

        result, receipt = search("traceseal")
        assert result == [{"result": "traceseal"}]
        assert receipt.execution["tool_name"] == "my_search"
        assert receipt.execution["transport"] == "python"
        assert receipt.execution["ok"] == "true"

    def test_default_name_from_function(self, key):
        @observe_tool_fn(operator_key=key)
        def my_unique_function_name():
            return 42

        result, receipt = my_unique_function_name()
        assert result == 42
        # The default name is module.qualname
        assert "my_unique_function_name" in receipt.execution["tool_name"]

    def test_sink_mode_preserves_signature(self, key):
        receipts = []

        @observe_tool_fn(
            operator_key=key,
            tool_name="search",
            receipt_sink=receipts.append,
        )
        def search(query: str) -> list:
            return [{"q": query}]

        # Original signature preserved — returns only the result
        result = search("hello")
        assert result == [{"q": "hello"}]

        # But the receipt was captured via the sink
        assert len(receipts) == 1
        assert receipts[0].execution["tool_name"] == "search"

    def test_decorator_captures_exceptions(self, key):
        @observe_tool_fn(operator_key=key, tool_name="broken")
        def broken():
            raise RuntimeError("oops")

        result, receipt = broken()
        assert result is None
        assert receipt.execution["ok"] == "false"
        assert "oops" in receipt.execution["error_message"]


class TestObserveMcpTool:
    def test_records_server_and_tool(self, key):
        result, receipt = observe_mcp_tool(
            server_name="filesystem",
            tool_name="read_file",
            arguments={"path": "/etc/hosts"},
            operator_key=key,
            call=lambda: {"content": "127.0.0.1 localhost"},
        )
        assert result == {"content": "127.0.0.1 localhost"}
        assert receipt.execution["tool_name"] == "filesystem/read_file"
        assert receipt.execution["transport"] == "mcp"
        assert receipt.execution["endpoint"] == "mcp://filesystem"

    def test_mcp_failure_sealed(self, key):
        result, receipt = observe_mcp_tool(
            server_name="github",
            tool_name="create_issue",
            arguments={"repo": "x", "title": "y"},
            operator_key=key,
            call=lambda: (_ for _ in ()).throw(Exception("API error")),
        )
        assert result is None
        assert receipt.execution["ok"] == "false"


class TestObserveHttpTool:
    def test_records_url_and_method(self, key):
        result, receipt = observe_http_tool(
            tool_name="wordpress_publish",
            url="https://example.com/wp-json/wp/v2/posts",
            method="POST",
            operator_key=key,
            call=lambda: {"status": 201, "post_id": 42},
            request_body={"title": "Test", "content": "Body"},
            headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
        )
        assert result == {"status": 201, "post_id": 42}
        assert receipt.execution["tool_name"] == "wordpress_publish"
        assert receipt.execution["transport"] == "http"
        assert receipt.execution["endpoint"] == "https://example.com/wp-json/wp/v2/posts"

    def test_headers_not_hashed_as_values(self, key):
        """Header values should NOT be included in the input hash —
        only the key names. Otherwise we'd leak auth tokens."""

        # Call twice with same body but different auth header values
        _, r1 = observe_http_tool(
            tool_name="t",
            url="https://api.com/x",
            method="GET",
            operator_key=key,
            call=lambda: {},
            request_body={"q": "test"},
            headers={"Authorization": "Bearer token1"},
        )
        _, r2 = observe_http_tool(
            tool_name="t",
            url="https://api.com/x",
            method="GET",
            operator_key=key,
            call=lambda: {},
            request_body={"q": "test"},
            headers={"Authorization": "Bearer token2_different"},
        )
        # Input hashes should be the same because only the key names were hashed
        assert r1.execution["input_hash"] == r2.execution["input_hash"]


class TestObserveShellTool:
    def test_successful_command(self, key):
        result, receipt = observe_shell_tool(
            tool_name="echo_test",
            command=["echo", "hello"],
            operator_key=key,
        )
        assert result is not None
        assert result.returncode == 0
        assert "hello" in result.stdout
        assert receipt.execution["ok"] == "true"
        assert receipt.execution["tool_name"] == "echo_test"
        assert receipt.execution["transport"] == "shell"

    def test_failed_command(self, key):
        # Run a command that returns non-zero
        result, receipt = observe_shell_tool(
            tool_name="false_test",
            command=["false"],
            operator_key=key,
        )
        assert result is not None
        assert result.returncode == 1
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["exit_code"] == 1

    def test_env_keys_recorded_not_values(self, key):
        # Same command, different env VALUES (but same KEYS) should hash same
        _, r1 = observe_shell_tool(
            tool_name="env_test",
            command=["echo", "test"],
            operator_key=key,
            env={"SECRET": "value_one", "PATH": "/usr/bin"},
        )
        _, r2 = observe_shell_tool(
            tool_name="env_test",
            command=["echo", "test"],
            operator_key=key,
            env={"SECRET": "completely_different", "PATH": "/usr/bin"},
        )
        # Input hashes are equal — env values were NOT included
        assert r1.execution["input_hash"] == r2.execution["input_hash"]

    def test_nonexistent_command_handled(self, key):
        result, receipt = observe_shell_tool(
            tool_name="bad",
            command=["this_command_does_not_exist_12345"],
            operator_key=key,
        )
        assert result is None
        assert receipt.execution["ok"] == "false"


class TestToolReceiptCrossVerification:
    """Tool receipts should verify with the existing standalone verifier."""

    def test_tool_receipt_verifies_with_traceseal_verify(self, key):
        try:
            from traceseal_verify import verify_receipt
        except ImportError:
            pytest.skip("traceseal-verify not installed; skipping cross-verify test")

        _, receipt = observe_tool(
            tool_name="search",
            operator_key=key,
            call=lambda: ["r1", "r2", "r3"],
            args={"q": "test"},
        )
        result = verify_receipt(receipt.to_dict())
        assert result.ok is True
        assert result.operator_fingerprint == key.fingerprint
