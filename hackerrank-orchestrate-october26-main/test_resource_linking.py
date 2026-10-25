"""
Test resource linking for all 32 sample cases
"""

import csv
import json
from datetime import datetime, timedelta

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_out = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    acts = list(csv.DictReader(f))

with open("dataset/user_identities.csv", encoding="utf-8") as f:
    identities = {r["email"].lower(): r for r in csv.DictReader(f)}
    id_by_uid = {r["user_id"]: r for r in identities.values()}

with open("dataset/user_audit_log.csv", encoding="utf-8") as f:
    for a in csv.DictReader(f):
        if a.get("field_name") == "email" and a.get("old_value"):
            identities[a["old_value"].lower()] = id_by_uid.get(a["user_id"])

total_target_resources = 0
total_found_resources = 0

for r in sample_reqs:
    cid = r["case_id"]
    email = r["email"].strip().lower()
    user = identities.get(email)
    uid = user["user_id"] if user else None

    gt_status, gt_steps = sample_out[cid]
    gt_rids = {s["resource_id"] for s in gt_steps}
    total_target_resources += len(gt_rids)

    rep_at = datetime.fromisoformat(r["reported_at"].replace("Z", "+00:00"))
    req_at = datetime.fromisoformat(r["requested_at"].replace("Z", "+00:00"))

    # Strategy:
    # 1. Activities in window [rep_at - 2h, rep_at + 2h]
    # 2. Check if details or rid match uid or email
    # 3. Check for deletion worker batches
    matched_rids = set()
    for a in acts:
        t = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
        # Direct identifier match
        if uid and (uid in str(a) or email in str(a).lower()):
            matched_rids.add(a["resource_id"])

    overlap = gt_rids & matched_rids
    total_found_resources += len(overlap)
    # print(f"{cid}: found {len(overlap)}/{len(gt_rids)}")

print(f"Direct match found: {total_found_resources}/{total_target_resources}")
