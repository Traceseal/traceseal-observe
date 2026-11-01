"""verify-pack compares report files byte for byte, so analysis output must
not depend on Python's hash seed (set iteration order)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[1] / "src")
HERE = Path(__file__).resolve().parent

ORDER_SCRIPT = r'''
import json
from traceseal_observe import OperatorKey, sign_execution_receipt, agent_context
from traceseal_observe.oversight import sign_oversight
from traceseal_observe.context import Principal
from traceseal_observe.trace import verify_trace
key = OperatorKey.from_raw_bytes("det", bytes(range(32)))
rev = Principal("service", "id:reviewer-bot")
rs = []
with agent_context(session_id="s-1"):
    for i in range(6):
        rs.append(sign_oversight(decision="stopped", operator_key=key, reviewer=rev,
                                 decided_at=f"2026-10-01T10:0{i}:00Z"))
    ctx = dict(rs[0].execution["context"])
tool = sign_execution_receipt({"receipt_type": "tool", "tool_name": "t", "context": ctx},
                              {"provenance_version": "1.0", "provider_attestation": "none"}, key)
rep = verify_trace(rs + [tool])
idx = {r.receipt_hash[:15]: i for i, r in enumerate(rs)}
print(json.dumps([idx[e.split("stop ")[1][:15]] for e in rep["errors"]
                  if "cannot order against the human stop" in e]))
'''


def _run(args, seed):
    env = dict(os.environ, PYTHONHASHSEED=str(seed), PYTHONPATH=SRC)
    return subprocess.run([sys.executable, *args], env=env, capture_output=True, text=True,
                          check=True).stdout


def test_stop_errors_follow_receipt_order_for_any_hash_seed():
    for seed in (0, 1, 2, 3, 4):
        assert json.loads(_run(["-c", ORDER_SCRIPT], seed)) == [0, 1, 2, 3, 4, 5]


def test_pack_built_under_one_seed_verifies_under_others(tmp_path):
    key = _run([str(HERE / "_det_build_rich.py"), str(tmp_path)], 11).strip().splitlines()[-1]
    check = ("import sys, json; from traceseal_observe.report import verify_pack; "
             f"r = verify_pack({str(tmp_path / 'pack')!r}, [{key!r}]); "
             "print(json.dumps([r['ok'], r['problems']]))")
    for seed in (0, 1, 2, 3):
        ok, problems = json.loads(_run(["-c", check], seed))
        assert ok, (seed, problems)
