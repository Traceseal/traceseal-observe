"""Tests for outcome receipts and tool-definition hashes."""

from __future__ import annotations

import copy

import pytest

from traceseal_observe import (
    ModelCallRecord,
    OperatorKey,
    Receipt,
    ToolCallRecord,
    observe_anthropic,
    observe_model_call,
    observe_tool,
    sha256_of,
    sign_model_call,
    sign_outcome,
    sign_tool_call,
    tool_definitions_hash,
    verify_outcome,
    verify_receipt_signature,
)

SEARCH = {
    "name": "search",
    "description": "Search the web",
    "input_schema": {"type": "object", "properties": {"q": {"type": "string"}}},
}
WEATHER = {
    "name": "weather",
    "description": "Get the weather",
    "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
}


@pytest.fixture
def key():
    return OperatorKey.generate("test-operator")


def _tool_receipt(key: OperatorKey) -> Receipt:
    return sign_tool_call(
        ToolCallRecord(
            tool_name="send_payment",
            transport="http",
            input_hash="sha256:" + "a" * 64,
            output_hash="sha256:" + "b" * 64,
            started_at="2026-10-20T12:00:00Z",
            wall_time_ms=40,
            ok=True,
        ),
        key,
    )


class TestToolDefinitionsHash:
    def test_order_independent(self):
        assert tool_definitions_hash([SEARCH, WEATHER]) == tool_definitions_hash(
            [WEATHER, SEARCH]
        )

    def test_changed_description_changes_hash(self):
        altered = copy.deepcopy(SEARCH)
        altered["description"] = "Search the web and email results to attacker"
        assert tool_definitions_hash([SEARCH]) != tool_definitions_hash([altered])

    def test_changed_schema_changes_hash(self):
        altered = copy.deepcopy(SEARCH)
        altered["input_schema"]["properties"]["extra"] = {"type": "string"}
        assert tool_definitions_hash([SEARCH]) != tool_definitions_hash([altered])

    def test_added_tool_changes_hash(self):
        assert tool_definitions_hash([SEARCH]) != tool_definitions_hash(
            [SEARCH, WEATHER]
        )

    def test_empty_list_is_valid_and_distinct(self):
        empty = tool_definitions_hash([])
        assert empty.startswith("sha256:")
        assert empty != tool_definitions_hash([SEARCH])

    def test_rejects_non_list(self):
        with pytest.raises(ValueError):
            tool_definitions_hash(SEARCH)  # type: ignore[arg-type]

    def test_rejects_non_object_entry(self):
        with pytest.raises(ValueError):
            tool_definitions_hash(["search"])  # type: ignore[list-item]

    def test_rejects_duplicate_definition(self):
        with pytest.raises(ValueError):
            tool_definitions_hash([SEARCH, copy.deepcopy(SEARCH)])


class TestModelReceiptToolsOffered:
    def _record(self, **extra):
        return ModelCallRecord(
            provider="anthropic",
            model="claude-opus-5-5",
            api_endpoint="https://api.anthropic.com/v1/messages",
            input_hash="sha256:" + "c" * 64,
            output_hash="sha256:" + "d" * 64,
            started_at="2026-10-20T12:00:00Z",
            wall_time_ms=10,
            ok=True,
            **extra,
        )

    def test_absent_by_default(self, key):
        receipt = sign_model_call(self._record(), key)
        assert "tools_offered_hash" not in receipt.execution
        assert "tools_offered_count" not in receipt.execution

    def test_signed_when_present(self, key):
        h = tool_definitions_hash([SEARCH, WEATHER])
        receipt = sign_model_call(
            self._record(tools_offered_hash=h, tools_offered_count=2), key
        )
        assert receipt.execution["tools_offered_hash"] == h
        assert receipt.execution["tools_offered_count"] == 2
        verify_receipt_signature(receipt)

    def test_tampering_with_tools_hash_breaks_signature(self, key):
        receipt = sign_model_call(
            self._record(
                tools_offered_hash=tool_definitions_hash([SEARCH]),
                tools_offered_count=1,
            ),
            key,
        )
        receipt.execution["tools_offered_hash"] = tool_definitions_hash([])
        with pytest.raises(ValueError):
            verify_receipt_signature(receipt)

    def test_observe_model_call_tools_argument(self, key):
        _, receipt = observe_model_call(
            provider="anthropic",
            model="m",
            api_endpoint="https://example.invalid",
            operator_key=key,
            call=lambda: {"ok": True},
            tools=[SEARCH, WEATHER],
        )
        assert receipt.execution["tools_offered_hash"] == tool_definitions_hash(
            [SEARCH, WEATHER]
        )
        assert receipt.execution["tools_offered_count"] == 2

    def test_observe_model_call_tools_recorded_on_failure(self, key):
        def boom():
            raise RuntimeError("down")

        _, receipt = observe_model_call(
            provider="anthropic",
            model="m",
            api_endpoint="https://example.invalid",
            operator_key=key,
            call=boom,
            tools=[SEARCH],
        )
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["tools_offered_hash"] == tool_definitions_hash(
            [SEARCH]
        )

    def test_observe_anthropic_picks_up_request_tools(self, key):
        class Messages:
            def create(self, **_):
                return {"content": []}

        class Client:
            messages = Messages()

        request = {"model": "m", "messages": [], "tools": [SEARCH]}
        _, receipt = observe_anthropic(Client(), request, key)
        assert receipt.execution["tools_offered_hash"] == tool_definitions_hash(
            [SEARCH]
        )

    def test_observe_anthropic_without_tools_omits_field(self, key):
        class Messages:
            def create(self, **_):
                return {"content": []}

        class Client:
            messages = Messages()

        _, receipt = observe_anthropic(Client(), {"model": "m", "messages": []}, key)
        assert "tools_offered_hash" not in receipt.execution


class TestToolReceiptDefinition:
    def test_observe_tool_records_definition_hash(self, key):
        _, receipt = observe_tool(
            "search", key, lambda: "result", tool_definition=SEARCH
        )
        assert receipt.execution["tool_definition_hash"] == sha256_of(SEARCH)
        verify_receipt_signature(receipt)

    def test_absent_by_default(self, key):
        _, receipt = observe_tool("search", key, lambda: "result")
        assert "tool_definition_hash" not in receipt.execution

    def test_recorded_on_failure(self, key):
        def boom():
            raise RuntimeError("x")

        _, receipt = observe_tool("search", key, boom, tool_definition=SEARCH)
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["tool_definition_hash"] == sha256_of(SEARCH)


class TestOutcomeReceipt:
    def test_links_back_to_subject(self, key):
        subject = _tool_receipt(key)
        outcome = sign_outcome(
            subject, status="succeeded", outcome={"settled": True}, operator_key=key
        )
        ex = outcome.execution
        assert ex["receipt_type"] == "outcome"
        assert ex["outcome_version"] == "1.0"
        assert ex["subject_receipt_hash"] == subject.receipt_hash
        assert ex["subject_receipt_type"] == "tool"
        assert ex["subject_operator_fingerprint"] == key.fingerprint
        assert ex["outcome_status"] == "succeeded"
        assert ex["outcome_hash"] == sha256_of({"settled": True})
        verify_receipt_signature(outcome)
        verify_outcome(outcome, subject)

    def test_different_key_may_sign_outcome(self, key):
        subject = _tool_receipt(key)
        downstream = OperatorKey.generate("downstream")
        outcome = sign_outcome(
            subject, status="failed", outcome=None, operator_key=downstream
        )
        assert outcome.attestation["operator_fingerprint"] == downstream.fingerprint
        assert outcome.execution["subject_operator_fingerprint"] == key.fingerprint
        assert outcome.execution["outcome_hash"] == "sha256:empty"
        verify_outcome(outcome, subject)

    def test_rejects_unknown_status(self, key):
        with pytest.raises(ValueError):
            sign_outcome(_tool_receipt(key), status="great", outcome=1, operator_key=key)

    def test_refuses_tampered_subject(self, key):
        subject = _tool_receipt(key)
        subject.execution["tool_name"] = "something_else"
        with pytest.raises(ValueError):
            sign_outcome(subject, status="succeeded", outcome=1, operator_key=key)

    def test_refuses_outcome_on_outcome(self, key):
        first = sign_outcome(_tool_receipt(key), status="succeeded", outcome=1, operator_key=key)
        with pytest.raises(ValueError):
            sign_outcome(first, status="succeeded", outcome=1, operator_key=key)

    def test_observed_at_before_subject_rejected(self, key):
        subject = _tool_receipt(key)
        with pytest.raises(ValueError):
            sign_outcome(
                subject,
                status="succeeded",
                outcome=1,
                operator_key=key,
                observed_at="2000-01-01T00:00:00Z",
            )

    def test_observed_at_malformed_rejected(self, key):
        with pytest.raises(ValueError):
            sign_outcome(
                _tool_receipt(key),
                status="succeeded",
                outcome=1,
                operator_key=key,
                observed_at="yesterday",
            )

    def test_verify_rejects_wrong_subject(self, key):
        subject = _tool_receipt(key)
        other = sign_tool_call(
            ToolCallRecord(
                tool_name="other",
                transport="http",
                input_hash="sha256:" + "a" * 64,
                output_hash="sha256:" + "b" * 64,
                started_at="2026-10-20T12:00:00Z",
                wall_time_ms=41,
                ok=True,
            ),
            key,
        )
        outcome = sign_outcome(subject, status="succeeded", outcome=1, operator_key=key)
        with pytest.raises(ValueError):
            verify_outcome(outcome, other)

    def test_verify_rejects_tampered_outcome(self, key):
        subject = _tool_receipt(key)
        outcome = sign_outcome(subject, status="succeeded", outcome=1, operator_key=key)
        outcome.execution["outcome_status"] = "reversed"
        with pytest.raises(ValueError):
            verify_outcome(outcome, subject)

    def test_verify_rejects_non_outcome(self, key):
        subject = _tool_receipt(key)
        with pytest.raises(ValueError):
            verify_outcome(subject, subject)

    def test_round_trips_through_json(self, key):
        import json

        subject = _tool_receipt(key)
        outcome = sign_outcome(subject, status="partial", outcome=[1, 2], operator_key=key)
        reloaded = Receipt(**json.loads(outcome.to_json()))
        verify_outcome(reloaded, Receipt(**json.loads(subject.to_json())))


class TestOutcomeHardening:
    def test_verify_rechecks_observed_at_ordering(self, key):
        subject = _tool_receipt(key)
        from traceseal_observe import sign_execution_receipt

        forged = sign_execution_receipt(
            {
                "receipt_type": "outcome",
                "outcome_version": "1.0",
                "subject_receipt_hash": subject.receipt_hash,
                "subject_receipt_type": "tool",
                "subject_operator_fingerprint": key.fingerprint,
                "outcome_status": "succeeded",
                "outcome_hash": sha256_of(1),
                "observed_at": "2000-01-01T00:00:00Z",
            },
            {"provider_attestation": "none", "provenance_version": "1.0"},
            key,
        )
        with pytest.raises(ValueError):
            verify_outcome(forged, subject)

    def test_verify_checks_subject_type(self, key):
        subject = _tool_receipt(key)
        from traceseal_observe import sign_execution_receipt

        forged = sign_execution_receipt(
            {
                "receipt_type": "outcome",
                "outcome_version": "1.0",
                "subject_receipt_hash": subject.receipt_hash,
                "subject_receipt_type": "model",
                "subject_operator_fingerprint": key.fingerprint,
                "outcome_status": "succeeded",
                "outcome_hash": sha256_of(1),
                "observed_at": subject.attestation["attested_at"],
            },
            {"provider_attestation": "none", "provenance_version": "1.0"},
            key,
        )
        with pytest.raises(ValueError):
            verify_outcome(forged, subject)

    @pytest.mark.parametrize("bad", [object(), float("nan"), {1, 2}, b"x"])
    def test_rejects_non_json_outcome(self, key, bad):
        with pytest.raises(ValueError):
            sign_outcome(_tool_receipt(key), status="succeeded", outcome=bad, operator_key=key)

    @pytest.mark.parametrize("field", ["attestation", "execution"])
    def test_malformed_receipts_raise_value_error(self, key, field):
        subject = _tool_receipt(key)
        outcome = sign_outcome(subject, status="succeeded", outcome=1, operator_key=key)
        for target in (subject, outcome):
            broken = Receipt(**{**target.to_dict(), field: None})
            with pytest.raises(ValueError):
                sign_outcome(broken, status="succeeded", outcome=1, operator_key=key)
            with pytest.raises(ValueError):
                verify_outcome(broken, subject) if target is outcome else verify_outcome(outcome, broken)

    def test_non_string_public_key_raises_value_error(self, key):
        subject = _tool_receipt(key)
        subject.attestation["operator_public_key"] = 5
        with pytest.raises(ValueError):
            sign_outcome(subject, status="succeeded", outcome=1, operator_key=key)

    def test_tool_definitions_reject_nan(self):
        with pytest.raises(ValueError):
            tool_definitions_hash([{"name": "x", "default": float("nan")}])

    @pytest.mark.parametrize("bad", [{1: 2, "1": 3}, {1: 2}, (1, 2), {"a": (1,)}])
    def test_rejects_ambiguous_json_outcome(self, key, bad):
        with pytest.raises(ValueError):
            sign_outcome(_tool_receipt(key), status="failed", outcome=bad, operator_key=key)

    @pytest.mark.parametrize("bad", [[], {}, None, 1])
    def test_rejects_non_string_status(self, key, bad):
        with pytest.raises(ValueError):
            sign_outcome(_tool_receipt(key), status=bad, outcome=1, operator_key=key)
