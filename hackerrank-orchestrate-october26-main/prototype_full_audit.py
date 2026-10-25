"""
Prototype Full Audit Engine
Evaluates against sample_output.csv
"""

import csv
import json
from datetime import datetime, timedelta
import sys
sys.path.insert(0, 'code')
from build_observations import observations
from audit_engine import (
    resolve_user, get_all_identifiers, is_deletion_request,
    sort_and_renumber, evidence_files, evidence_by_id,
    system_activity
)

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_gt = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

# Index observations by (user_id), (email), and (resource_id)
obs_by_user = {}
obs_by_email = {}
obs_by_resource = {}

for o in observations:
    if o.get("user_id"):
        obs_by_user.setdefault(o["user_id"], []).append(o)
    if o.get("email"):
        obs_by_email.setdefault(o["email"].lower(), []).append(o)
    if o.get("resource_id"):
        obs_by_resource.setdefault(o["resource_id"], []).append(o)

# Index activities by resource_id
act_by_resource = {}
for a in system_activity:
    act_by_resource.setdefault(a["resource_id"], []).append(a)

def audit_case(case: dict) -> dict:
    cid = case["case_id"]
    email = case["email"].strip()
    req_text = case["request_text"].strip()
    audit_at_str = case["audit_at"].strip()
    audit_at = datetime.fromisoformat(audit_at_str.replace("Z", "+00:00"))
    rep_at_str = case["reported_at"].strip()
    rep_at = datetime.fromisoformat(rep_at_str.replace("Z", "+00:00"))
    req_at_str = case["requested_at"].strip()
    req_at = datetime.fromisoformat(req_at_str.replace("Z", "+00:00"))

    # 1. Identity
    user = resolve_user(email)
    if not user:
        return {"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    # 2. Deletion Intent
    if not is_deletion_request(req_text):
        return {"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    uid = user["user_id"]
    idents = get_all_identifiers(user)

    # 3. Best primary evidence file at audit_at
    ev_candidates = [
        ef for ef in evidence_files
        if datetime.fromisoformat(ef["captured_at"].replace("Z", "+00:00")) <= audit_at
    ]
    ev_candidates.sort(key=lambda x: datetime.fromisoformat(x["captured_at"].replace("Z", "+00:00")), reverse=True)
    primary_ev = ev_candidates[0]["file_id"] if ev_candidates else ""

    # 4. Gather candidate resources for this user
    user_obs = []
    for em in idents["emails"]:
        user_obs.extend(obs_by_email.get(em, []))
    user_obs.extend(obs_by_user.get(uid, []))

    # Also find activities in window [req_at - 1h, rep_at + 1h]
    window_acts = []
    for a in system_activity:
        t = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
        if req_at - timedelta(hours=1) <= t <= rep_at + timedelta(hours=1):
            window_acts.append(a)

    return {"case_id": cid, "user": uid, "user_obs": len(user_obs), "window_acts": len(window_acts)}

print("Testing first 10 sample cases:")
for r in sample_reqs[:10]:
    res = audit_case(r)
    print(res)
