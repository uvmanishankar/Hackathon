"""
Test combining evidence observations and system_activity linking across all 518 cases
"""

import csv
from datetime import datetime, timedelta
from build_observations import observations

with open("dataset/deletion_requests.csv", encoding="utf-8") as f:
    requests = list(csv.DictReader(f))

with open("dataset/user_identities.csv", encoding="utf-8") as f:
    identities = {r["email"].lower(): r for r in csv.DictReader(f)}
    id_by_uid = {r["user_id"]: r for r in identities.values()}

with open("dataset/user_audit_log.csv", encoding="utf-8") as f:
    for a in csv.DictReader(f):
        if a.get("field_name") == "email" and a.get("old_value"):
            identities[a["old_value"].lower()] = id_by_uid.get(a["user_id"])

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    acts = list(csv.DictReader(f))

# Index activities by user/email
act_by_user = {}
for a in acts:
    det = a.get("details", "")
    rid = a.get("resource_id", "")
    for u in identities.values():
        uid = u["user_id"]
        em = u["email"].lower()
        if uid in det or em in det.lower() or uid in rid:
            act_by_user.setdefault(uid, []).append(a)

covered = 0
for r in requests:
    cid = r["case_id"]
    em = r["email"].strip().lower()
    user = identities.get(em)
    uid = user["user_id"] if user else None

    # Check obs
    has_obs = any((o.get("user_id") == uid or (o.get("email") or "").lower() == em) for o in observations)
    has_act = bool(act_by_user.get(uid))
    if has_obs or has_act:
        covered += 1

print(f"Total covered with obs + acts: {covered}/518")
