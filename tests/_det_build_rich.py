"""Build a rich evidence pack into argv[1]; print the operator public key."""
import json, sys
from pathlib import Path
from traceseal_observe import (OperatorKey, sign_execution_receipt, sign_incident, agent_context,
                               observe_tool)
from traceseal_observe.oversight import sign_oversight, sign_policy_decision
from traceseal_observe.report import build_pack
from traceseal_observe.context import Principal

out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
key = OperatorKey.from_private_bytes(bytes(range(32))) if hasattr(OperatorKey, "from_private_bytes") else OperatorKey.generate()
REV = Principal("service", "id:reviewer-bot") if True else None
rs = []
with agent_context(session_id="s-1"):
    s1 = sign_oversight(decision="stopped", operator_key=key, reviewer=REV, decided_at="2026-10-01T10:00:00Z")
    s2 = sign_oversight(decision="stopped", operator_key=key, reviewer=REV, decided_at="2026-10-01T10:00:00Z")
    res = sign_oversight(decision="resumed", operator_key=key, reviewer=REV, subjects=[s1, s2],
                         decided_at="2026-10-01T10:00:00Z")
    rs += [s1, s2, res, observe_tool("t1", key, lambda: 1)[1], observe_tool("t2", key, lambda: 2)[1]]
for i, host in enumerate(["b.example.com", "a.example.com", "c.example.com"]):
    rs.append(sign_policy_decision(policy_id=f"p{i}", decision=["allow", "deny", "flag"][i], stage="output",
                                   decided_at=f"2026-10-01T11:0{i}:00Z", operator_key=key))
for cat in ("serious_incident", "personal_data_breach", "significant_incident", "major_ict_incident"):
    rs.append(sign_incident(category=cat, severity="high", status="detected",
                            aware_at="2026-09-01T00:00:00Z", operator_key=key))
paths = []
for i, r in enumerate(rs):
    p = out / f"in-{i:02d}.json"; p.write_text(r.to_json()); paths.append(p)
build_pack(out / "pack", paths, operator_key=key, operator_keys=[key.public_key_hex],
           require_approval=["t1"], required_scopes={"t2": ["a:b"]})
print(key.public_key_hex)
