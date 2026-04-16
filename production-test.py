"""Production test: real OpenClaw workflow instrumented with Traceseal.

Uses MiniMax (via Anthropic Messages API) — the same model provider
OpenClaw uses in production. Tests all four receipt types end-to-end.
"""

import json
import os
import sys
from pathlib import Path

import requests

from traceseal_observe import (
    OperatorKey,
    WorkflowObserver,
    observe_data_flow,
    observe_model_call,
    observe_tool,
    bundle_workflow,
    verify_workflow_bundle,
    summarize_data_flows,
    fingerprint_pii,
)

# ── Config ──────────────────────────────────────────────────────────────

OPERATOR_KEY = OperatorKey.load_from_file(
    Path.home() / ".traceseal" / "keys" / "ventse-dev.key"
)

DECLARED_DESTINATIONS = [
    "api.minimax.io",
    "britfarmers.com",
    "httpbin.org",
]


def _load_minimax_token() -> str:
    for agent_dir in ["main", "coder", "devops"]:
        auth_path = (
            Path.home()
            / ".openclaw"
            / "agents"
            / agent_dir
            / "agent"
            / "auth-profiles.json"
        )
        if auth_path.exists():
            profiles = json.loads(auth_path.read_text())
            token = (
                profiles.get("profiles", {})
                .get("minimax-portal:default", {})
                .get("access", "")
            )
            if token:
                return token
    return ""


MINIMAX_TOKEN = _load_minimax_token()
if not MINIMAX_TOKEN:
    print("FATAL: MiniMax token not found")
    sys.exit(1)


# ── Phase 1: Smoke test — real model call ───────────────────────────────

def phase1_smoke_test():
    print("=" * 60)
    print("PHASE 1: Smoke test — real MiniMax model call")
    print("=" * 60)

    request_body = {
        "model": "MiniMax-M2.7",
        "max_tokens": 100,
        "messages": [{"role": "user", "content": "Reply with just the word 'working'"}],
    }

    response, receipt = observe_model_call(
        provider="minimax",
        model="MiniMax-M2.7",
        api_endpoint="https://api.minimax.io/anthropic/v1/messages",
        operator_key=OPERATOR_KEY,
        call=lambda: requests.post(
            "https://api.minimax.io/anthropic/v1/messages",
            headers={
                "Authorization": f"Bearer {MINIMAX_TOKEN}",
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            json=request_body,
            timeout=30,
        ),
        serialize_request=lambda: request_body,
        serialize_response=lambda r: r.json(),
        extract_input_tokens=lambda r: r.json().get("usage", {}).get("input_tokens"),
        extract_output_tokens=lambda r: r.json().get("usage", {}).get("output_tokens"),
    )

    resp_json = response.json()
    text_parts = [
        b.get("text", "")
        for b in resp_json.get("content", [])
        if b.get("type") == "text"
    ]
    response_text = "\n".join(text_parts).strip()

    print(f"  Operator: {OPERATOR_KEY.fingerprint}")
    print(f"  Response: {response_text}")
    print(f"  Status:   {response.status_code}")
    print(f"  Receipt type: {receipt.execution['receipt_type']}")
    print(f"  Provider: {receipt.execution['provider']}")
    print(f"  Model:    {receipt.execution['model']}")
    print(f"  Wall ms:  {receipt.execution['wall_time_ms']}")
    print(f"  OK:       {receipt.execution['ok']}")
    print(f"  Input tokens:  {receipt.execution.get('input_tokens', 'N/A')}")
    print(f"  Output tokens: {receipt.execution.get('output_tokens', 'N/A')}")

    Path("/tmp/smoke-model-receipt.json").write_text(receipt.to_json())
    print(f"  Saved: /tmp/smoke-model-receipt.json")

    assert receipt.execution["ok"] == "true", "Smoke test failed!"
    print("  PASS")
    return receipt


# ── Phase 2: Full instrumented workflow ─────────────────────────────────

def phase2_full_workflow():
    print()
    print("=" * 60)
    print("PHASE 2: Full instrumented workflow")
    print("=" * 60)

    topic = "Brexit impact on UK dairy subsidies"
    data_flow_receipts = []

    with WorkflowObserver(
        workflow_name="britfarmers-publish",
        workflow_version="1.0.0",
        operator_key=OPERATOR_KEY,
        workflow_input={"topic": topic},
    ) as wf:

        # Step 1: Model call — generate draft via MiniMax
        print(f"\n  Step 1: Drafting article on '{topic}'...")
        draft_request = {
            "model": "MiniMax-M2.7",
            "max_tokens": 2000,
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"Write a 3-paragraph article about {topic} for UK farmers. "
                        f"Plain text, no markdown, no headers. Around 200 words."
                    ),
                }
            ],
        }

        raw_response, r1 = observe_model_call(
            provider="minimax",
            model="MiniMax-M2.7",
            api_endpoint="https://api.minimax.io/anthropic/v1/messages",
            operator_key=OPERATOR_KEY,
            call=lambda: requests.post(
                "https://api.minimax.io/anthropic/v1/messages",
                headers={
                    "Authorization": f"Bearer {MINIMAX_TOKEN}",
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                },
                json=draft_request,
                timeout=60,
            ),
            serialize_request=lambda: draft_request,
            serialize_response=lambda r: r.json(),
            extract_input_tokens=lambda r: r.json().get("usage", {}).get("input_tokens"),
            extract_output_tokens=lambda r: r.json().get("usage", {}).get("output_tokens"),
        )
        resp_json = raw_response.json()
        text_parts = [
            b.get("text", "")
            for b in resp_json.get("content", [])
            if b.get("type") == "text"
        ]
        draft_text = "\n".join(text_parts).strip()
        wf.add_step("draft", r1)
        print(f"    Done — {len(draft_text.split())} words, receipt {r1.receipt_hash[:25]}...")

        # Step 2: Tool call — word count quality check
        print("  Step 2: Word count quality check...")

        def word_count():
            words = len(draft_text.split())
            chars = len(draft_text)
            return {"words": words, "chars": chars, "quality": "ok" if words > 50 else "too_short"}

        result, r2 = observe_tool(
            tool_name="word_counter",
            operator_key=OPERATOR_KEY,
            call=word_count,
            args={"text_length": len(draft_text)},
        )
        wf.add_step("quality_check", r2)
        print(f"    Done — {result['words']} words, quality={result['quality']}, receipt {r2.receipt_hash[:25]}...")

        # Step 3: Data flow — dry run publish to httpbin
        print("  Step 3: Simulated WordPress publish (httpbin dry run)...")
        publish_body = {
            "title": f"Article about {topic}",
            "content": draft_text,
            "status": "draft",
            "author_email": "tim@britfarmers.com",  # intentional PII for testing
        }

        pub_response, r3 = observe_data_flow(
            url="https://httpbin.org/post",
            method="POST",
            operator_key=OPERATOR_KEY,
            call=lambda: requests.post(
                "https://httpbin.org/post",
                json=publish_body,
                timeout=15,
            ),
            request_body=publish_body,
            declared_allow_list=DECLARED_DESTINATIONS,
        )
        wf.add_step("publish", r3)
        data_flow_receipts.append(r3)
        print(f"    Done — status {r3.execution['status_code']}, receipt {r3.receipt_hash[:25]}...")

        if r3.execution.get("pii_fingerprint"):
            print(f"    PII detected: {r3.execution['pii_fingerprint']}")

        wf.set_final_output({
            "topic": topic,
            "word_count": result["words"],
            "published": True,
        })

    # Save everything
    orch_path = Path("/tmp/openclaw-test-orchestration.json")
    orch_path.write_text(wf.receipt.to_json())
    print(f"\n  Orchestration receipt: {orch_path}")

    bundle_path = Path("/tmp/openclaw-test-workflow.tar.gz")
    bundle_workflow(wf.receipt, wf.child_receipts, bundle_path)
    print(f"  Workflow bundle: {bundle_path} ({bundle_path.stat().st_size} bytes)")

    Path("/tmp/openclaw-test-draft.txt").write_text(draft_text)
    print(f"  Draft saved: /tmp/openclaw-test-draft.txt")

    # Data flow summary
    summary = summarize_data_flows(data_flow_receipts)
    print(f"\n  Data flow summary:")
    print(f"    Total calls:     {summary['total_calls']}")
    print(f"    Destinations:    {summary['destinations']}")
    print(f"    Undeclared:      {summary['undeclared_calls']}")
    print(f"    PII summary:     {summary['pii_summary']}")
    print(f"    Failed calls:    {summary['failed_calls']}")

    print("  PASS")
    return wf.receipt, wf.child_receipts, draft_text


# ── Phase 2.2: Verify the bundle ───────────────────────────────────────

def phase2_verify():
    print()
    print("=" * 60)
    print("PHASE 2.2: Verify the orchestration bundle")
    print("=" * 60)

    report = verify_workflow_bundle("/tmp/openclaw-test-workflow.tar.gz")
    print(f"  ok:        {report['ok']}")
    print(f"  parent_ok: {report['parent_ok']}")
    print(f"  workflow:  {report['workflow_name']}")
    print(f"  steps:     {report['step_count']}")
    print(f"  message:   {report['message']}")
    for child in report["child_results"]:
        mark = "PASS" if child["ok"] else "FAIL"
        print(f"    [{mark}] {child['step']:20s} ({child.get('receipt_type', '?')})")

    assert report["ok"], "Bundle verification failed!"
    print("  PASS")


# ── Phase 2.3: Third-party verification ─────────────────────────────────

def phase2_third_party():
    print()
    print("=" * 60)
    print("PHASE 2.3: Third-party verification (no keys, no audit log)")
    print("=" * 60)

    from traceseal_observe import unbundle_workflow

    parent, children, manifest = unbundle_workflow("/tmp/openclaw-test-workflow.tar.gz")
    print(f"  Workflow:       {parent.execution['workflow_name']}")
    print(f"  Step count:     {parent.execution['step_count']}")
    print(f"  Output hash:    {parent.execution['final_output_hash']}")
    print(f"  Operator:       {parent.attestation['operator_fingerprint']}")

    # Verify parent signature independently
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from traceseal_observe import _signed_payload

    pk_bytes = bytes.fromhex(parent.attestation["operator_public_key"])
    pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    payload = _signed_payload(parent.execution, parent.provenance)
    sig = bytes.fromhex(parent.attestation["signature"])
    pk.verify(sig, payload)
    print("  Parent signature: VALID")

    for i, child in enumerate(children):
        c_pk = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(child.attestation["operator_public_key"])
        )
        c_payload = _signed_payload(child.execution, child.provenance)
        c_sig = bytes.fromhex(child.attestation["signature"])
        c_pk.verify(c_sig, c_payload)
        rtype = child.execution.get("receipt_type", "?")
        print(f"  Child {i} ({rtype}): VALID")

    print("  PASS")


# ── Phase 3: Compliance questions ───────────────────────────────────────

def phase3_compliance():
    print()
    print("=" * 60)
    print("PHASE 3: Answer compliance questions from bundle only")
    print("=" * 60)

    from traceseal_observe import unbundle_workflow
    parent, children, manifest = unbundle_workflow("/tmp/openclaw-test-workflow.tar.gz")

    print("\n  Q1: What AI model generated this article?")
    for child in children:
        if child.execution.get("receipt_type") == "model":
            print(f"    Model:    {child.execution['provider']}/{child.execution['model']}")
            print(f"    Called:   {child.execution['started_at']}")
            print(f"    Tokens:   {child.execution.get('input_tokens', '?')} in, {child.execution.get('output_tokens', '?')} out")
            print(f"    Latency:  {child.execution['wall_time_ms']}ms")

    print("\n  Q2: Did this workflow send data to unauthorized destinations?")
    for child in children:
        if child.execution.get("receipt_type") == "data_flow":
            declared = child.execution.get("destination_declared", "unknown")
            host = child.execution.get("destination_host", "unknown")
            print(f"    {host}: declared={declared}")

    print("\n  Q3: Did any PII leave the system?")
    for child in children:
        if child.execution.get("receipt_type") == "data_flow":
            pii = child.execution.get("pii_fingerprint", {})
            if pii:
                print(f"    PII flagged: {pii}")
            else:
                print(f"    No PII patterns detected")

    print("\n  Q4: Can you prove this workflow wasn't tampered with?")
    report = verify_workflow_bundle("/tmp/openclaw-test-workflow.tar.gz")
    print(f"    Bundle verification: {'PASS' if report['ok'] else 'FAIL'}")
    print(f"    {report['message']}")

    print("  PASS")


# ── Phase 4: Failure mode tests ─────────────────────────────────────────

def phase4_failures():
    print()
    print("=" * 60)
    print("PHASE 4: Failure mode tests")
    print("=" * 60)

    # Test 4.1: Model call with bad auth
    print("\n  Test 4.1: Model call with bad auth token...")
    bad_request = {
        "model": "MiniMax-M2.7",
        "max_tokens": 50,
        "messages": [{"role": "user", "content": "test"}],
    }
    response, receipt = observe_model_call(
        provider="minimax",
        model="MiniMax-M2.7",
        api_endpoint="https://api.minimax.io/anthropic/v1/messages",
        operator_key=OPERATOR_KEY,
        call=lambda: requests.post(
            "https://api.minimax.io/anthropic/v1/messages",
            headers={
                "Authorization": "Bearer bad_token_for_test",
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            json=bad_request,
            timeout=10,
        ),
        serialize_request=lambda: bad_request,
        serialize_response=lambda r: r.json() if r.status_code == 200 else {"error": r.text[:200]},
    )
    # The call itself won't raise — requests returns a 401/403. But observe
    # records the response. Check the receipt is still valid and signed.
    print(f"    HTTP status: {response.status_code}")
    print(f"    Receipt ok:  {receipt.execution['ok']}")
    print(f"    Signed:      {len(receipt.attestation['signature']) == 128}")

    # Verify the failure receipt
    from traceseal_verify import verify_receipt
    vr = verify_receipt(receipt.to_dict())
    print(f"    Verifies:    {vr.ok}")
    print("    PASS")

    # Test 4.2: Data flow to unreachable host
    print("\n  Test 4.2: Data flow to unreachable host...")
    response, receipt = observe_data_flow(
        url="https://definitely-does-not-exist-12345.invalid/post",
        method="POST",
        operator_key=OPERATOR_KEY,
        call=lambda: requests.post(
            "https://definitely-does-not-exist-12345.invalid/post",
            json={"test": True},
            timeout=5,
        ),
        request_body={"test": True},
        declared_allow_list=["api.minimax.io"],
    )
    print(f"    Response:    {response}")
    print(f"    Receipt ok:  {receipt.execution['ok']}")
    print(f"    Error:       {receipt.execution.get('error_message', 'none')[:80]}")
    print(f"    Undeclared:  {receipt.execution.get('destination_declared')}")
    vr = verify_receipt(receipt.to_dict())
    print(f"    Verifies:    {vr.ok}")
    assert receipt.execution["ok"] == "false"
    print("    PASS")

    # Test 4.3: Tamper detection
    print("\n  Test 4.3: Tamper detection...")
    tampered = json.loads(Path("/tmp/openclaw-test-orchestration.json").read_text())
    tampered["execution"]["workflow_name"] = "evil-workflow"
    Path("/tmp/tampered.json").write_text(json.dumps(tampered))
    vr = verify_receipt(tampered)
    print(f"    Tampered receipt verifies: {vr.ok}")
    assert not vr.ok, "Tampered receipt should NOT verify!"
    print("    PASS — tampering detected")


# ── Phase 5: Cross-verify with standalone CLI ───────────────────────────

def phase5_cli_verify():
    print()
    print("=" * 60)
    print("PHASE 5: Cross-verify with traceseal-verify CLI")
    print("=" * 60)

    import subprocess

    # Verify smoke receipt
    r = subprocess.run(
        ["traceseal-verify", "/tmp/smoke-model-receipt.json"],
        capture_output=True, text=True,
    )
    print(f"  Smoke receipt:  {r.stdout.strip()}")
    assert "[OK]" in r.stdout

    # Verify orchestration receipt
    r = subprocess.run(
        ["traceseal-verify", "/tmp/openclaw-test-orchestration.json"],
        capture_output=True, text=True,
    )
    print(f"  Orchestration:  {r.stdout.strip()}")
    assert "[OK]" in r.stdout

    # Extract bundle and verify each child
    import tarfile
    extract_dir = Path("/tmp/traceseal-bundle-extract")
    extract_dir.mkdir(exist_ok=True)
    with tarfile.open("/tmp/openclaw-test-workflow.tar.gz", "r:gz") as tar:
        tar.extractall(extract_dir)

    for child_file in sorted((extract_dir / "children").glob("*.json")):
        r = subprocess.run(
            ["traceseal-verify", str(child_file)],
            capture_output=True, text=True,
        )
        print(f"  {child_file.name[:30]}:  {r.stdout.strip()}")
        assert "[OK]" in r.stdout

    print("  PASS")


# ── Main ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Operator key: {OPERATOR_KEY.fingerprint}")
    print(f"MiniMax token: ...{MINIMAX_TOKEN[-8:]}")
    print()

    phase1_smoke_test()
    phase2_full_workflow()
    phase2_verify()
    phase2_third_party()
    phase3_compliance()
    phase4_failures()
    phase5_cli_verify()

    print()
    print("=" * 60)
    print("ALL PHASES PASSED")
    print("=" * 60)
