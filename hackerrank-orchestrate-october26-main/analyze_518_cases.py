"""
Analyze the 518 cases in deletion_requests.csv
"""

import csv
from collections import Counter
from datetime import datetime

with open("dataset/deletion_requests.csv", encoding="utf-8") as f:
    requests = list(csv.DictReader(f))

with open("dataset/user_identities.csv", encoding="utf-8") as f:
    identities = {r["email"].lower(): r for r in csv.DictReader(f)}
    id_by_uid = {r["user_id"]: r for r in identities.values()}

with open("dataset/user_audit_log.csv", encoding="utf-8") as f:
    for a in csv.DictReader(f):
        if a.get("field_name") == "email" and a.get("old_value"):
            identities[a["old_value"].lower()] = id_by_uid.get(a["user_id"])

with open("dataset/evidence_files.csv", encoding="utf-8") as f:
    evidence = list(csv.DictReader(f))

print(f"Total requests: {len(requests)}")

# 1. Identity resolution check
resolved = 0
unresolved = []
for r in requests:
    em = r["email"].strip().lower()
    if em in identities:
        resolved += 1
    else:
        unresolved.append(r)

print(f"Identities resolved: {resolved}/{len(requests)}")
if unresolved:
    print(f"Unresolved sample: {unresolved[:3]}")

# 2. Status distribution in input
status_counts = Counter(r["reported_status"] for r in requests)
print(f"Reported status distribution: {dict(status_counts)}")

# 3. Audit cutoff dates distribution
audit_dates = Counter(r["audit_at"][:10] for r in requests)
print(f"Audit dates count: {len(audit_dates)} distinct dates")
for d, c in audit_dates.most_common(10):
    print(f"  {d}: {c} cases")
