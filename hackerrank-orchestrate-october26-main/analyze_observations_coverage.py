"""
Analyze observation coverage across the 518 cases
"""

import csv
from collections import defaultdict
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

# Index observations by user_id and email
obs_by_uid = defaultdict(list)
obs_by_email = defaultdict(list)
for o in observations:
    if o.get("user_id"):
        obs_by_uid[o["user_id"]].append(o)
    if o.get("email"):
        obs_by_email[o["email"].lower()].append(o)

# Check coverage of each of the 518 cases
covered_cases = 0
uncovered = []
for r in requests:
    cid = r["case_id"]
    em = r["email"].strip().lower()
    user = identities.get(em)
    uid = user["user_id"] if user else None

    user_obs = obs_by_uid.get(uid, []) + obs_by_email.get(em, [])
    # Deduplicate by (evidence_id, resource_id)
    seen = set()
    uniq = []
    for o in user_obs:
        k = (o["evidence_id"], o["resource_id"])
        if k not in seen:
            seen.add(k)
            uniq.append(o)

    if uniq:
        covered_cases += 1
    else:
        uncovered.append((cid, uid, em))

print(f"Cases with direct observations: {covered_cases}/518")
print(f"Uncovered cases: {len(uncovered)}")
if uncovered:
    print(f"Sample uncovered: {uncovered[:5]}")
