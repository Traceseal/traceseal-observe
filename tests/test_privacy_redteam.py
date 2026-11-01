"""Regression tests for the 2026-11 privacy red-team findings (1.6.0).

Receipts are signed and shared, so nothing secret or personal may be
written into them: URLs, error text, PII counts, erasure receipts,
principals and destination checks.
"""

from __future__ import annotations

import hashlib
import json
import warnings

import pytest

httpx = pytest.importorskip("httpx2")

from traceseal_observe import (
    OperatorKey,
    _client_endpoint,
    _redact_error,
    error_text,
    fingerprint_pii,
    observe_data_flow,
    observe_http_tool,
    observe_tool,
    sanitize_url,
    set_error_text,
)
from traceseal_observe.capture import (
    ReceiptTransport,
    UndeclaredDestination,
    UnreceiptedRouteWarning,
    check_client,
    receipted_client,
)
from traceseal_observe.context import Principal, agent_context
from traceseal_observe.vault import EvidenceVault, LocalKEK, VaultError


@pytest.fixture
def key():
    return OperatorKey.generate("t")


def _transport(key, receipts, sent=None, **kw):
    def handler(request):
        if sent is not None:
            sent.append(str(request.url))
        return httpx.Response(200, json={"ok": True})

    return ReceiptTransport(httpx.MockTransport(handler), operator_key=key,
                            on_receipt=receipts.append, **kw)


# ---------------------------------------------------------------------------
# 1. URL sanitising
# ---------------------------------------------------------------------------


class TestSanitizeUrl:
    @pytest.mark.parametrize("url, expected", [
        ("https://svc:hunter2@gw.example.com/v1/messages?key=Q#frag",
         "https://gw.example.com/v1/messages"),
        ("https://gw.example.com/v1;api_key=SEMICOLONSECRET", "https://gw.example.com/v1"),
        ("https://gw.example.com/v1#tok=FRAGSECRET", "https://gw.example.com/v1"),
        ("https://gw.example.com/sk-proxykey-PATHSECRET/v1", "https://gw.example.com/{redacted}/v1"),
        ("https://gw.example.com/a1B2c3D4e5F6g7H8i9J0/v1", "https://gw.example.com/{redacted}/v1"),
        ("https://hooks.slack.com/services/T000/B000/XXXXSLACKWEBHOOKSECRET",
         "https://hooks.slack.com/services/{redacted}/{redacted}/{redacted}"),
        ("https://discord.com/api/webhooks/123456/abcdefTOKEN",
         "https://discord.com/api/{redacted}/{redacted}/{redacted}"),
        ("https://maker.ifttt.com/trigger/evt/with/key/abcdef",
         "https://maker.ifttt.com/trigger/{redacted}/{redacted}/{redacted}/{redacted}"),
        ("https://api.example.com/users/alice@example.com/x",
         "https://api.example.com/users/{redacted}/x"),
        ("https://API.Example.COM:8443/v1", "https://api.example.com:8443/v1"),
        ("user:PWNOSCHEME@gw.example.com/v1", "gw.example.com/v1"),
        ("http://h:99999/", "{redacted}"),
        # Ordinary API paths, model names and deployment ids survive.
        ("https://api.minimax.io/v1/text/chatcompletion_v2",
         "https://api.minimax.io/v1/text/chatcompletion_v2"),
        ("https://bedrock-runtime.us-east-1.amazonaws.com/model/"
         "anthropic.claude-3-5-sonnet-20240620-v1:0/invoke",
         "https://bedrock-runtime.us-east-1.amazonaws.com/model/"
         "anthropic.claude-3-5-sonnet-20240620-v1:0/invoke"),
        ("https://x.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions",
         "https://x.openai.azure.com/openai/deployments/gpt-4o-mini/chat/completions"),
    ])
    def test_cases(self, url, expected):
        assert sanitize_url(url) == expected

    def test_host_only(self):
        assert sanitize_url("https://u:p@a.example.com:8443/x/y?q=1", host_only=True) \
            == "https://a.example.com:8443"

    def test_idempotent(self):
        once = sanitize_url("https://hooks.slack.com/services/T/B/X")
        assert sanitize_url(once) == once

    def test_transport_drops_userinfo_and_webhook_tokens(self, key):  # red team t1
        rs = []
        c = httpx.Client(transport=_transport(
            key, rs, allow_hosts=["gw.example.com", "hooks.slack.com"], block_undeclared=True))
        c.post("https://svc:hunter2-SECRET@gw.example.com/v1/messages?key=QSECRET", json={"a": 1}).read()
        c.post("https://hooks.slack.com/services/T000/B000/XXXXSLACKWEBHOOKSECRET", json={"t": 1}).read()
        assert rs[0].execution["destination_url"] == "https://gw.example.com/v1/messages"
        assert rs[1].execution["destination_url"] == \
            "https://hooks.slack.com/services/{redacted}/{redacted}/{redacted}"
        dumped = json.dumps([r.to_dict() for r in rs])
        for secret in ("hunter2", "QSECRET", "SLACKWEBHOOKSECRET", "T000"):
            assert secret not in dumped

    def test_transport_host_only(self, key):
        rs = []
        c = httpx.Client(transport=_transport(key, rs, host_only=True))
        c.get("https://api.example.com/v1/users/42").read()
        assert rs[0].execution["destination_url"] == "https://api.example.com"

    def test_observe_http_tool_endpoint(self, key):  # red team t2(a)
        _, r = observe_http_tool(
            "search", "https://u:PASSW0RD@api.example.com/v1/q?api_key=sk-live-QUERYSECRET",
            "GET", key, lambda: {"ok": 1})
        assert r.execution["endpoint"] == "https://api.example.com/v1/q"
        _, r = observe_http_tool("search", "https://api.example.com/v1/q", "GET", key,
                                 lambda: {"ok": 1}, host_only=True)
        assert r.execution["endpoint"] == "https://api.example.com"

    def test_observe_tool_url_endpoint_sanitised(self, key):
        _, r = observe_tool("t", key, lambda: 1, endpoint="https://u:p@x.example.com/a?k=v")
        assert r.execution["endpoint"] == "https://x.example.com/a"
        _, r = observe_tool("t", key, lambda: 1, endpoint="mcp://filesystem")
        assert r.execution["endpoint"] == "mcp://filesystem"

    def test_observe_data_flow_url(self, key):  # red team t2(d)
        def boom():
            raise httpx.ConnectError("[Errno 111] Connection refused: https://svc:PWLEAK@10.0.0.5:8443/ingest")

        _, r = observe_data_flow("https://svc:PWLEAK@10.0.0.5:8443/ingest?t=1", "POST", key, boom,
                                 request_body={"x": 1})
        assert r.execution["destination_url"] == "https://10.0.0.5:8443/ingest"
        assert "PWLEAK" not in json.dumps(r.to_dict())
        _, r = observe_data_flow("https://api.example.com/v1/x", "POST", key, lambda: None,
                                 host_only=True)
        assert r.execution["destination_url"] == "https://api.example.com"

    @pytest.mark.parametrize("base, expected", [  # red team t3
        ("https://user:pw@gw.example.com/v1?key=Q", "https://gw.example.com/v1/v1/messages"),
        (httpx.URL("https://user:pw@gw.example.com/v1/?key=Q"), "https://gw.example.com/v1/v1/messages"),
        ("https://gw.example.com/v1;api_key=SEMICOLONSECRET", "https://gw.example.com/v1/v1/messages"),
        ("https://gw.example.com/sk-proxykey-PATHSECRET/v1", "https://gw.example.com/{redacted}/v1/v1/messages"),
        ("user:PWNOSCHEME@gw.example.com/v1", "https://api.anthropic.com/v1/messages"),
        ("https://gw.example.com/v1#tok=FRAGSECRET", "https://gw.example.com/v1/v1/messages"),
    ])
    def test_client_endpoint(self, base, expected):
        class C:
            base_url = base

        assert _client_endpoint(C(), "https://api.anthropic.com", "v1/messages") == expected


# ---------------------------------------------------------------------------
# 2. Error text
# ---------------------------------------------------------------------------


def _short(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


class TestErrorText:
    def test_default_is_type_and_hash(self):
        msg = "request failed, headers={'Authorization': 'Bearer sk-ant-api03-AAAABBBBCCCCDDDD'}"
        assert _redact_error(f"ValueError: {msg}") == f"ValueError (sha256:{_short(msg)})"
        assert _redact_error(ValueError(msg)) == f"ValueError (sha256:{_short(msg)})"
        assert _redact_error("ValueError: ") == "ValueError"
        assert _redact_error("no type prefix") == f"Error (sha256:{_short('no type prefix')})"

    def test_failure_paths_use_default(self, key):  # red team t2(c)
        def tool():
            raise ValueError("123-45-6789 (Alice Smith, alice@example.com)")

        _, r = observe_tool("lookup", key, tool, args={"ssn": "x"})
        assert r.execution["error_message"].startswith("ValueError (sha256:")
        assert "Alice" not in json.dumps(r.to_dict())

    def test_pydantic_input_value_not_recorded(self, key):
        pydantic = pytest.importorskip("pydantic")

        class Args(pydantic.BaseModel):
            ssn: int

        def tool():
            return Args(ssn="123-45-6789 (Alice Smith, alice@example.com)")

        _, r = observe_tool("lookup", key, tool)
        assert "Alice" not in r.execution["error_message"]
        with error_text("scrubbed"):
            _, r = observe_tool("lookup", key, tool)
        msg = r.execution["error_message"]
        assert msg.startswith("ValidationError: ") and "input_value={redacted}" in msg
        assert "Alice" not in msg and "123-45" not in msg and "alice@" not in msg

    @pytest.mark.parametrize("message, secrets, kept", [  # red team t2(b), t10
        ("HTTPStatusError: Client error '401 Unauthorized' for url 'https://admin:S3cretPw@db.internal/x'",
         ["S3cretPw", "admin:"], ["401 Unauthorized", "https://db.internal/x"]),
        ("ValueError: request failed, headers={'Authorization': 'Bearer sk-ant-api03-AAAABBBBCCCCDDDD'}",
         ["sk-ant", "AAAABBBB"], ["Authorization"]),
        ("RuntimeError: callback https://app/cb#access_token=ya29.FRAGMENTTOKEN&expires_in=3599",
         ["FRAGMENTTOKEN", "access_token"], ["https://app/cb"]),
        ("ConnectError: POST body api_key=sk-proj-FORMBODYSECRET&user=alice@example.com",
         ["FORMBODYSECRET", "alice@example.com"], ["api_key={redacted}", "{email}"]),
        ("RuntimeError: proxy rejected Authorization: Bearer sk-proj-LIVEKEY1234567890abcdef",
         ["LIVEKEY"], ["proxy rejected"]),
        ("X: sent Bearer abcdefgh123 and Basic dXNlcjpwYXNz", ["abcdefgh123", "dXNlcjpwYXNz"], ["Bearer {redacted}"]),
        ("KeyError: {'password': 'hunter2 two', 'n': 1}", ["hunter2"], ["'n': 1"]),
        ("ConnectError: refused: svc:PWLEAK@10.0.0.5:8443/ingest", ["PWLEAK", "10.0.0.5"], ["refused"]),
        ("ValueError: card 4111 1111 1111 1111 ssn 123-45-6789", ["4111", "123-45"],
         ["{credit_card}", "{ssn}"]),
    ])
    def test_scrubbed_mode(self, message, secrets, kept):
        out = _redact_error(message, mode="scrubbed")
        for s in secrets:
            assert s not in out, out
        for k in kept:
            assert k in out, out

    def test_scrub_before_truncation(self):
        msg = "E: " + "x" * 190 + " token=sk-live-abcdefghijklmnopqrstuvwxyz"
        assert "sk-live" not in _redact_error(msg, mode="scrubbed")
        assert len(_redact_error(msg, mode="scrubbed")) <= 200

    def test_global_opt_in(self, key):
        set_error_text("scrubbed")
        try:
            _, r = observe_tool("t", key, lambda: (_ for _ in ()).throw(RuntimeError("kaboom")))
        finally:
            set_error_text("hash")
        assert r.execution["error_message"] == "RuntimeError: kaboom"
        with pytest.raises(ValueError):
            set_error_text("raw")

    def test_langchain_call_style(self):
        """traceseal-langchain calls _redact_error(f"{type(e).__name__}: {e}")."""
        e = RuntimeError("proxy rejected Authorization: Bearer sk-proj-LIVEKEY1234567890abcdef")
        out = _redact_error(f"{type(e).__name__}: {e}")
        assert out == f"RuntimeError (sha256:{_short(str(e))})"

    def test_transport_error_hashed(self, key):
        rs = []

        def handler(request):
            raise httpx.ConnectError("refused https://u:SECRETPW@h.example.com/x")

        c = httpx.Client(transport=ReceiptTransport(httpx.MockTransport(handler), operator_key=key,
                                                    on_receipt=rs.append))
        with pytest.raises(httpx.ConnectError):
            c.get("https://h.example.com/x")
        assert rs[0].execution["error_message"].startswith("ConnectError (sha256:")


# ---------------------------------------------------------------------------
# 3. PII counting
# ---------------------------------------------------------------------------


class TestPiiCounting:
    LINES = "Customer:\n4111 1111 1111 1111\n123-45-6789\n415-555-0100\n"
    TABS = "card\t4111111111111111\tssn\t123-45-6789"

    def test_escaped_newlines_and_tabs_in_dicts(self):  # red team t4
        want = {"credit_card": 1, "ssn": 1, "phone_us": 1}
        assert fingerprint_pii({"messages": [{"role": "user", "content": self.LINES}]}) == want
        assert fingerprint_pii({"m": self.TABS}) == {"credit_card": 1, "ssn": 1}

    def test_json_bytes_are_decoded(self):
        body = json.dumps({"messages": [{"content": self.LINES}]}).encode()
        assert fingerprint_pii(body) == {"credit_card": 1, "ssn": 1, "phone_us": 1}

    def test_non_json_bytes_treat_escapes_as_separators(self):
        body = json.dumps({"content": self.LINES}).encode()[:-3]  # truncated: not valid JSON
        assert fingerprint_pii(body)["ssn"] == 1
        assert fingerprint_pii(b"x\\u0020alice@example.com\\nssn\\t123-45-6789") == {"email": 1, "ssn": 1}

    def test_values_do_not_join_across_fields(self):
        assert fingerprint_pii({"a": "415", "b": "555-0100"}) == {}

    def test_transport_counts_newline_prompt(self, key):
        rs = []
        c = httpx.Client(transport=_transport(key, rs))
        c.post("https://api.anthropic.com/v1/messages",
               json={"messages": [{"role": "user", "content": self.LINES}]}).read()
        assert rs[0].execution["pii_fingerprint"] == {"credit_card": 1, "phone_us": 1, "ssn": 1}
        assert "pii_scan_truncated" not in rs[0].execution

    def test_transport_marks_truncated_scan(self, key):
        rs = []
        c = httpx.Client(transport=_transport(key, rs))
        big = {"messages": [{"content": "x" * (1 << 20) + " ssn 123-45-6789"}]}
        c.post("https://api.anthropic.com/v1/messages", json=big).read()
        ex = rs[0].execution
        assert ex["pii_scan_truncated"] == "true"
        assert ex["pii_scan_bytes"] == 1 << 20
        assert ex["payload_bytes"] > 1 << 20


# ---------------------------------------------------------------------------
# 4. Vault
# ---------------------------------------------------------------------------


class TestVaultPrivacy:
    def test_domain_hash_is_keyed(self, tmp_path, key):  # red team t5
        v = EvidenceVault.open(tmp_path / "v", kek=LocalKEK.generate())
        v.put("p", domain="tenant:acme")
        expected = v.domain_hash("tenant:acme")
        er = v.shred("tenant:acme", operator_key=key)
        h = er.execution["domain_hash"]
        assert h == expected and h.startswith("hmac-sha256:")
        assert h[len("hmac-sha256:"):] != hashlib.sha256(b"tenant:acme").hexdigest()
        assert er.execution["erasure_version"] == "1.1"
        # A different vault (different salt) gives a different hash.
        other = EvidenceVault.open(tmp_path / "w", kek=LocalKEK.generate())
        assert other.domain_hash("tenant:acme") != h

    def test_salt_persists_and_is_added_to_old_vaults(self, tmp_path):
        kek = LocalKEK.generate()
        d = tmp_path / "v"
        (d / "domains").mkdir(parents=True)
        (d / "vault.json").write_text(json.dumps({"vault_version": "1.0", "min_retention_days": 7}))
        v = EvidenceVault.open(d, kek=kek)
        meta = json.loads((d / "vault.json").read_text())
        assert meta["vault_version"] == "1.1" and meta["domain_salt"] and meta["min_retention_days"] == 7
        assert EvidenceVault.open(d, kek=kek).domain_hash("x") == v.domain_hash("x")

    def test_override_needs_operator_key(self, tmp_path, key):  # red team t6
        v = EvidenceVault.open(tmp_path / "v", kek=LocalKEK.generate(), min_retention_days=183)
        h = v.put("log line", domain="period:2026-11")
        with pytest.raises(VaultError, match="needs operator_key"):
            v.shred("period:2026-11", override_retention=True)
        assert v.get(h) == "log line"  # nothing destroyed
        er = v.shred("period:2026-11", operator_key=key, override_retention=True)
        assert er.execution["retention_overridden"] == "true"


# ---------------------------------------------------------------------------
# 5. Principals
# ---------------------------------------------------------------------------


class TestPrincipal:
    def test_raw_user_ref_rejected(self):  # red team t8
        with pytest.raises(ValueError, match="keyed commitments"):
            Principal("user", "id:alice@example.com")

    def test_commitments_and_public_ids_still_work(self, key):
        pepper = b"p" * 32
        p = Principal.user("alice@example.com", pepper=pepper)
        assert Principal("user", p.ref) == p
        assert Principal.committed("user", "alice", pepper=pepper).ref.startswith("hmac-sha256:")
        assert Principal.public("service", "billing").ref == "id:billing"
        with agent_context(principal=p):
            _, r = observe_tool("t", key, lambda: 1)
        assert r.execution["context"]["principal"]["ref"] == p.ref


# ---------------------------------------------------------------------------
# 6. Destination blocking
# ---------------------------------------------------------------------------


class TestDestinationBlocking:
    def _client(self, key, rs, sent, allow):
        return httpx.Client(transport=_transport(key, rs, sent, allow_hosts=allow, block_undeclared=True))

    @pytest.mark.parametrize("url, allowed", [  # red team t11
        ("https://API.ANTHROPIC.COM/v1", True),
        ("https://api.anthropic.com:443/v1", True),
        ("https://api.anthropic.com./v1", False),
        ("https://api.anthropic.com.evil.io/", False),
        ("http://api.anthropic.com/v1", False),
        ("http://api.anthropic.com:31337/plaintext", False),
        ("https://api.anthropic.com:8443/v1", False),
    ])
    def test_bare_host_means_https_443(self, key, url, allowed):
        rs, sent = [], []
        c = self._client(key, rs, sent, ["api.anthropic.com"])
        if allowed:
            c.get(url).read()
            assert sent and rs[0].execution["destination_declared"] == "true"
        else:
            with pytest.raises(UndeclaredDestination):
                c.get(url)
            assert not sent and rs[0].execution["destination_declared"] == "false"

    def test_explicit_http_entry(self, key):
        rs, sent = [], []
        c = self._client(key, rs, sent, ["http://localhost:8080", "https://gw.example.com:8443"])
        c.get("http://localhost:8080/x").read()
        c.get("https://gw.example.com:8443/x").read()
        for url in ("https://localhost:8080/x", "http://localhost:8081/x", "https://gw.example.com/x"):
            with pytest.raises(UndeclaredDestination):
                c.get(url)
        assert len(sent) == 2
        assert rs[0].execution["declared_allow_list"] == \
            ["http://localhost:8080", "https://gw.example.com:8443"]

    def test_bad_entries_rejected(self, key):
        for bad in ["https://u:p@h.example.com", "h.example.com/path", "ftp://h.example.com", "api.x.com"[:0]]:
            with pytest.raises(ValueError):
                _transport(key, [], allow_hosts=[bad])

    def test_mounts_bypass_is_detected(self, key):
        rs = []
        inner = httpx.MockTransport(lambda r: httpx.Response(200))
        c = httpx.Client(transport=_transport(key, rs), mounts={"https://evil.example": inner})
        with pytest.warns(UnreceiptedRouteWarning, match="evil.example"):
            assert check_client(c)
        with pytest.warns(UnreceiptedRouteWarning):
            receipted_client(httpx.Client, inner, operator_key=key, on_receipt=rs.append,
                             mounts={"https://evil.example": inner})
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            ok = receipted_client(httpx.Client, inner, operator_key=key, on_receipt=rs.append)
            assert check_client(ok) == []
        ok.get("https://api.example.com/").read()
        assert rs


class TestPass2Edges:
    """Second red-team pass: remaining URL and scrubbed-text gaps."""

    @pytest.mark.parametrize("url,secret", [
        ("https://gw.example.com/v1%3Bapi_key=SECRETSEMI/x", "SECRETSEMI"),
        ("https://gw.example.com/key=hunter2pass/x", "hunter2pass"),
        ("https://gw.example.com/passwd/hunter2/x", "hunter2"),
    ])
    def test_sanitize_url_edges(self, url, secret):
        from traceseal_observe import sanitize_url
        assert secret not in sanitize_url(url)

    def test_provider_urls_untouched(self):
        from traceseal_observe import sanitize_url
        for url in ("https://api.anthropic.com/v1/messages",
                    "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-x/invoke"):
            assert sanitize_url(url) == url

    @pytest.mark.parametrize("text,secret", [
        ("ValueError: bad key sk-proj-ABCDEFGHIJKLMNOPQRSTUV here", "sk-proj-ABCDEFGHIJKLMNOPQRSTUV"),
        ("KeyError: password 'hunter2' rejected", "hunter2"),
        ("RuntimeError: secret is: hunter2", "hunter2"),
        ("X: aws wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY bad", "wJalrXUtnFEMI"),
        ("X: call +44 20 7946 0958 now", "7946"),
    ])
    def test_scrubbed_text_edges(self, text, secret):
        assert secret not in _redact_error(text, mode="scrubbed")

    def test_plain_errors_stay_readable_when_scrubbed(self):
        msg = "TimeoutError: read timed out after 30 seconds on /v1/messages"
        assert _redact_error(msg, mode="scrubbed") == msg


def test_signing_refuses_values_every_verifier_rejects():
    from traceseal_observe import sign_execution_receipt
    k = OperatorKey.generate()
    for bad in ({"receipt_type": "tool", "flag": True}, {"receipt_type": "tool", "x": None}):
        with pytest.raises(ValueError, match="RECEIPT-SPEC"):
            sign_execution_receipt(bad, {"provenance_version": "1.0"}, k)
