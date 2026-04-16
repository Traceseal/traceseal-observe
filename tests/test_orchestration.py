"""Tests for orchestration receipts (Module 3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traceseal_observe import (
    OperatorKey,
    OrchestrationRecord,
    Receipt,
    WorkflowObserver,
    WorkflowStep,
    bundle_workflow,
    observe_anthropic,
    observe_http_tool,
    observe_mcp_tool,
    observe_model_call,
    observe_shell_tool,
    observe_tool,
    observe_tool_fn,
    sign_orchestration,
    unbundle_workflow,
    verify_workflow_bundle,
)


@pytest.fixture
def key():
    return OperatorKey.generate("test-operator")


def _fake_model_call(key, label="response"):
    """Helper to produce a fake model call receipt for testing."""
    _, receipt = observe_model_call(
        provider="anthropic",
        model="claude-sonnet-4-20250514",
        api_endpoint="https://api.anthropic.com/v1/messages",
        operator_key=key,
        call=lambda: {"content": label, "usage": {"input_tokens": 5, "output_tokens": 10}},
        serialize_request=lambda: {"prompt": label},
    )
    return receipt


def _fake_tool_call(key, tool="search", query="test"):
    """Helper to produce a fake tool call receipt."""
    _, receipt = observe_tool(
        tool_name=tool,
        operator_key=key,
        call=lambda: [{"url": "http://example.com", "query": query}],
        args={"query": query},
    )
    return receipt


class TestSignOrchestration:
    def test_produces_valid_orchestration_receipt(self, key):
        child1 = _fake_model_call(key, "first")
        child2 = _fake_tool_call(key, "search")

        record = OrchestrationRecord(
            workflow_name="test-workflow",
            workflow_version="1.0",
            steps=[
                WorkflowStep(
                    name="research",
                    receipt_hash=child1.receipt_hash,
                    receipt_type="model",
                    ok=True,
                ),
                WorkflowStep(
                    name="search",
                    receipt_hash=child2.receipt_hash,
                    receipt_type="tool",
                    ok=True,
                ),
            ],
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=500,
            ok=True,
        )
        receipt = sign_orchestration(record, key)
        assert receipt.receipt_version == "1.0"
        assert receipt.execution["receipt_type"] == "orchestration"
        assert receipt.execution["workflow_name"] == "test-workflow"
        assert receipt.execution["step_count"] == 2
        assert len(receipt.execution["steps"]) == 2
        assert receipt.execution["steps"][0]["name"] == "research"
        assert receipt.execution["steps"][0]["receipt_hash"] == child1.receipt_hash
        assert receipt.execution["ok"] == "true"

    def test_failed_workflow_records_error_step(self, key):
        record = OrchestrationRecord(
            workflow_name="test-workflow",
            workflow_version="1.0",
            steps=[
                WorkflowStep(
                    name="step1",
                    receipt_hash="sha256:abc",
                    receipt_type="tool",
                    ok=False,
                ),
            ],
            started_at="2026-04-15T12:00:00Z",
            wall_time_ms=100,
            ok=False,
            error_step="step1",
        )
        receipt = sign_orchestration(record, key)
        assert receipt.execution["ok"] == "false"
        assert receipt.execution["error_step"] == "step1"


class TestWorkflowObserver:
    def test_successful_workflow(self, key):
        child1 = _fake_model_call(key, "research")
        child2 = _fake_tool_call(key, "search")

        with WorkflowObserver(
            workflow_name="publish",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("research", child1)
            wf.add_step("search", child2)
            wf.set_final_output({"post_id": 42})

        assert wf.receipt is not None
        assert wf.receipt.execution["ok"] == "true"
        assert wf.receipt.execution["step_count"] == 2
        assert wf.receipt.execution["final_output_hash"] != "sha256:empty"

    def test_failed_child_marks_workflow_failed(self, key):
        """If any child has ok=false, the whole workflow is ok=false."""
        _, failed_child = observe_tool(
            tool_name="bad_tool",
            operator_key=key,
            call=lambda: (_ for _ in ()).throw(RuntimeError("oops")),
        )
        good_child = _fake_tool_call(key, "good")

        with WorkflowObserver(
            workflow_name="partial_fail",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("step1", good_child)
            wf.add_step("step2", failed_child)

        assert wf.receipt.execution["ok"] == "false"

    def test_exception_during_workflow_still_signs(self, key):
        child1 = _fake_tool_call(key, "step1")

        try:
            with WorkflowObserver(
                workflow_name="exception_test",
                workflow_version="1.0",
                operator_key=key,
            ) as wf:
                wf.add_step("step1", child1)
                wf.mark_failed_step("step2")
                raise RuntimeError("mid-workflow error")
        except RuntimeError:
            pass

        assert wf.receipt is not None
        assert wf.receipt.execution["ok"] == "false"
        assert wf.receipt.execution["error_step"] == "step2"

    def test_empty_workflow_valid(self, key):
        """A workflow with zero steps is valid (degenerate but legal)."""
        with WorkflowObserver(
            workflow_name="empty",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            pass
        assert wf.receipt.execution["step_count"] == 0

    def test_workflow_input_hash_recorded(self, key):
        with WorkflowObserver(
            workflow_name="with-input",
            workflow_version="1.0",
            operator_key=key,
            workflow_input={"user_id": 42, "action": "publish"},
        ) as wf:
            wf.add_step("s1", _fake_tool_call(key, "x"))

        # Input hash should not be empty
        assert wf.receipt.execution["workflow_input_hash"] != "sha256:empty"

    def test_child_receipts_accessible(self, key):
        child1 = _fake_tool_call(key, "a")
        child2 = _fake_tool_call(key, "b")

        with WorkflowObserver(
            workflow_name="test",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("s1", child1)
            wf.add_step("s2", child2)

        assert wf.child_receipts == [child1, child2]


class TestBundleWorkflow:
    def test_roundtrip(self, key, tmp_path):
        """Bundle, then unbundle, should round-trip correctly."""
        child1 = _fake_model_call(key, "research")
        child2 = _fake_tool_call(key, "search")

        with WorkflowObserver(
            workflow_name="test-bundle",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("research", child1)
            wf.add_step("search", child2)

        bundle_path = tmp_path / "workflow.tar.gz"
        bundle_workflow(wf.receipt, wf.child_receipts, bundle_path)

        assert bundle_path.exists()
        assert bundle_path.stat().st_size > 0

        # Unbundle
        parent, children, manifest = unbundle_workflow(bundle_path)
        assert parent.execution["workflow_name"] == "test-bundle"
        assert len(children) == 2
        assert children[0].receipt_hash == child1.receipt_hash
        assert children[1].receipt_hash == child2.receipt_hash
        assert manifest["workflow_name"] == "test-bundle"

    def test_bundle_detects_hash_mismatch(self, key, tmp_path):
        """If child list doesn't match parent's step list, bundle raises."""
        child1 = _fake_model_call(key, "first")
        child2 = _fake_tool_call(key, "second")
        child3 = _fake_tool_call(key, "third")

        with WorkflowObserver(
            workflow_name="test",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("step1", child1)
            wf.add_step("step2", child2)

        # Pass the WRONG children (child3 instead of child2) — should raise
        with pytest.raises(ValueError, match="does not match"):
            bundle_workflow(
                wf.receipt, [child1, child3], tmp_path / "bad.tar.gz"
            )

    def test_bundle_detects_count_mismatch(self, key, tmp_path):
        """Wrong number of children raises."""
        child1 = _fake_tool_call(key, "a")
        child2 = _fake_tool_call(key, "b")

        with WorkflowObserver(
            workflow_name="test",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("step1", child1)
            wf.add_step("step2", child2)

        with pytest.raises(ValueError, match="step count mismatch"):
            bundle_workflow(wf.receipt, [child1], tmp_path / "short.tar.gz")


class TestVerifyWorkflowBundle:
    def test_valid_bundle_verifies(self, key, tmp_path):
        child1 = _fake_model_call(key, "research")
        child2 = _fake_tool_call(key, "search")
        child3 = _fake_tool_call(key, "publish")

        with WorkflowObserver(
            workflow_name="publish-flow",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("research", child1)
            wf.add_step("search", child2)
            wf.add_step("publish", child3)
            wf.set_final_output({"url": "https://example.com/post/1"})

        bundle_path = tmp_path / "valid.tar.gz"
        bundle_workflow(wf.receipt, wf.child_receipts, bundle_path)

        report = verify_workflow_bundle(bundle_path)
        assert report["ok"] is True
        assert report["parent_ok"] is True
        assert report["step_count"] == 3
        assert all(c["ok"] for c in report["child_results"])
        assert report["workflow_name"] == "publish-flow"

    def test_tampered_child_breaks_verification(self, key, tmp_path):
        """If a child receipt is tampered inside the bundle, verify fails."""
        import tarfile
        import io

        child1 = _fake_tool_call(key, "step1")

        with WorkflowObserver(
            workflow_name="tamper_test",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("step1", child1)

        bundle_path = tmp_path / "tampered.tar.gz"
        bundle_workflow(wf.receipt, wf.child_receipts, bundle_path)

        # Rewrite the bundle, tampering with the child's execution data
        # but leaving its signature unchanged — this should fail verification
        with tarfile.open(bundle_path, "r:gz") as tar:
            members = tar.getmembers()
            contents = {}
            for m in members:
                f = tar.extractfile(m)
                if f:
                    contents[m.name] = f.read()

        # Find and tamper with the child file
        child_filename = None
        for name, data in contents.items():
            if name.startswith("children/"):
                child_data = json.loads(data)
                child_data["execution"]["tool_name"] = "DIFFERENT_TOOL"
                contents[name] = json.dumps(child_data).encode("utf-8")
                child_filename = name
                break
        assert child_filename is not None

        # Write back the tampered bundle
        tampered_path = tmp_path / "tampered2.tar.gz"
        with tarfile.open(tampered_path, "w:gz") as tar:
            for name, data in contents.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

        # The child hash in the manifest will no longer match
        report = verify_workflow_bundle(tampered_path)
        assert report["ok"] is False

    def test_multi_type_workflow(self, key, tmp_path):
        """Verify a workflow mixing model, tool, and shell receipts."""
        model_r = _fake_model_call(key, "plan")
        tool_r = _fake_tool_call(key, "search")
        _, shell_r = observe_shell_tool(
            tool_name="pwd",
            command=["pwd"],
            operator_key=key,
        )

        with WorkflowObserver(
            workflow_name="multi-type",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("plan", model_r)
            wf.add_step("search", tool_r)
            wf.add_step("checkpoint", shell_r)

        bundle_path = tmp_path / "multi.tar.gz"
        bundle_workflow(wf.receipt, wf.child_receipts, bundle_path)

        report = verify_workflow_bundle(bundle_path)
        assert report["ok"] is True
        types = sorted(c["receipt_type"] for c in report["child_results"])
        assert types == ["model", "tool", "tool"]  # shell is transport=shell but type=tool


class TestOrchestrationCrossCompat:
    """Orchestration receipts verify with the standalone traceseal-verify."""

    def test_orchestration_verifies_with_standalone_verifier(self, key):
        try:
            from traceseal_verify import verify_receipt as standalone_verify
        except ImportError:
            pytest.skip("traceseal-verify not installed; skipping cross-verify test")

        child1 = _fake_tool_call(key, "a")
        child2 = _fake_tool_call(key, "b")

        with WorkflowObserver(
            workflow_name="cross-verify",
            workflow_version="1.0",
            operator_key=key,
        ) as wf:
            wf.add_step("a", child1)
            wf.add_step("b", child2)

        result = standalone_verify(wf.receipt.to_dict())
        assert result.ok is True
        assert result.operator_fingerprint == key.fingerprint
