"""Security-hardening tests for the 2026-06-07 audit HIGH findings.

Covers (traceseal-observe):
  H3 — unbundle_workflow must verify receipt signatures by default
  H4 — error messages baked into receipts must not leak URL query-string credentials
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from traceseal_observe import (
    OperatorKey,
    Receipt,
    WorkflowObserver,
    bundle_workflow,
    observe_model_call,
    unbundle_workflow,
)


@pytest.fixture
def key():
    return OperatorKey.generate("test-operator")


def _fake_model_call(key, label="response"):
    _, receipt = observe_model_call(
        provider="anthropic",
        model="claude-sonnet-4-20250514",
        api_endpoint="https://api.anthropic.com/v1/messages",
        operator_key=key,
        call=lambda: {"content": label, "usage": {"input_tokens": 5, "output_tokens": 10}},
        serialize_request=lambda: {"prompt": label},
    )
    return receipt


def _make_bundle(key, tmp_path) -> Path:
    child = _fake_model_call(key, "research")
    with WorkflowObserver(
        workflow_name="sec-test",
        workflow_version="1.0",
        operator_key=key,
    ) as wf:
        wf.add_step("research", child)
    bundle_path = tmp_path / "workflow.tar.gz"
    bundle_workflow(wf.receipt, wf.child_receipts, bundle_path)
    return bundle_path


def _tamper_child(bundle_path: Path, out_path: Path) -> None:
    """Rewrite the bundle with a tampered child whose manifest hash is
    updated to match — defeating the hash check but not the signature."""
    members: dict[str, bytes] = {}
    with tarfile.open(bundle_path, "r:gz") as tar:
        for member in tar.getmembers():
            f = tar.extractfile(member)
            if f:
                members[member.name] = f.read()

    manifest = json.loads(members["MANIFEST.json"])
    child_name = manifest["children"][0]["filename"]
    child_data = json.loads(members[child_name])
    child_data["execution"]["model"] = "tampered-model"

    recomputed = Receipt(
        receipt_version=child_data["receipt_version"],
        execution=child_data["execution"],
        provenance=child_data["provenance"],
        attestation=child_data["attestation"],
    ).receipt_hash
    manifest["children"][0]["receipt_hash"] = recomputed

    members[child_name] = json.dumps(child_data).encode()
    members["MANIFEST.json"] = json.dumps(manifest).encode()

    with tarfile.open(out_path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


class TestUnbundleVerifiesSignatures:
    def test_clean_bundle_unbundles(self, key, tmp_path):
        bundle = _make_bundle(key, tmp_path)
        parent, children, manifest = unbundle_workflow(bundle)
        assert len(children) == 1

    def test_tampered_child_rejected_by_default(self, key, tmp_path):
        """H3: a hash-consistent but signature-invalid child must raise."""
        bundle = _make_bundle(key, tmp_path)
        bad = tmp_path / "tampered.tar.gz"
        _tamper_child(bundle, bad)
        with pytest.raises(ValueError, match="signature"):
            unbundle_workflow(bad)

    def test_verify_false_opts_out(self, key, tmp_path):
        """Back-compat escape hatch for callers doing their own verification."""
        bundle = _make_bundle(key, tmp_path)
        bad = tmp_path / "tampered.tar.gz"
        _tamper_child(bundle, bad)
        parent, children, manifest = unbundle_workflow(bad, verify=False)
        assert children[0].execution["model"] == "tampered-model"


class TestErrorMessageRedaction:
    def test_query_string_credentials_redacted(self, key):
        """H4: exception text containing a URL query string must be scrubbed
        before being signed into the receipt."""

        def failing_call():
            raise RuntimeError(
                "404 for url https://api.example.com/v1/messages"
                "?api_key=sk-SUPERSECRET123&user=tim"
            )

        response, receipt = observe_model_call(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            api_endpoint="https://api.example.com/v1/messages",
            operator_key=key,
            call=failing_call,
            serialize_request=lambda: {"prompt": "x"},
        )
        assert response is None
        msg = receipt.execution["error_message"]
        assert "sk-SUPERSECRET123" not in msg
        assert "RuntimeError" in msg
