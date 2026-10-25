"""
Test matching observations against sample ground truth
"""

import csv
import json
from datetime import datetime
from build_observations import observations

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_out = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

with open("dataset/user_identities.csv", encoding="utf-8") as f:
    identities = {r["email"].lower(): r for r in csv.DictReader(f)}
    id_by_uid = {r["user_id"]: r for r in identities.values()}

with open("dataset/user_audit_log.csv", encoding="utf-8") as f:
    for a in csv.DictReader(f):
        if a.get("field_name") == "email" and a.get("old_value"):
            identities[a["old_value"].lower()] = id_by_uid.get(a["user_id"])

# Match cases
matched_cases = 0
for r in sample_reqs:
    cid = r["case_id"]
    email = r["email"].strip().lower()
    audit_at = datetime.fromisoformat(r["audit_at"].replace("Z", "+00:00"))
    gt_status, gt_steps = sample_out[cid]

    u = identities.get(email)
    uid = u["user_id"] if u else None

    # Filter observations relevant to this user that occurred on or before audit_at
    user_obs = []
    for o in observations:
        cap_dt = datetime.fromisoformat(o["captured_at"].replace("Z", "+00:00"))
        if cap_dt > audit_at:
            continue
        o_em = (o.get("email") or "").lower()
        o_uid = o.get("user_id")
        if (uid and o_uid == uid) or (email and o_em == email):
            user_obs.append(o)

    # Compare with ground truth resources
    gt_resources = {s["resource_id"] for s in gt_steps}
    obs_resources = {o["resource_id"] for o in user_obs}
    overlap = gt_resources & obs_resources
    print(f"{cid:8s} {gt_status:11s}: GT res={len(gt_resources)}, Obs res={len(obs_resources)}, Overlap={len(overlap)}/{len(gt_resources)}")
    if len(overlap) < len(gt_resources):
        missing = gt_resources - obs_resources
        print(f"   Missing: {missing}")
