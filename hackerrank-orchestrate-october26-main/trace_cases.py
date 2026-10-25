"""
Test tracing deletion activities to requests by time window
"""

import csv
from datetime import datetime, timedelta

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/deletion_requests.csv", encoding="utf-8") as f:
    all_reqs = sample_reqs + list(csv.DictReader(f))

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    acts = list(csv.DictReader(f))

# Let's see how many requests have deletion worker activities matching their window
matched_count = 0
for r in sample_reqs:
    cid = r["case_id"]
    rep_at = datetime.fromisoformat(r["reported_at"].replace("Z", "+00:00"))
    req_at = datetime.fromisoformat(r["requested_at"].replace("Z", "+00:00"))

    # Window: from req_at to rep_at + 15m
    window_acts = []
    for a in acts:
        t = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
        if req_at <= t <= rep_at + timedelta(minutes=15):
            src = a.get("source_system", "")
            evt = a.get("event_type", "")
            det = a.get("details", "")
            if src == "deletion_worker" or any(w in evt for w in ["DELETE", "ANONYMIZE", "REDACT", "DISABLE", "BLOCK"]):
                window_acts.append(a)

    print(f"{cid}: rep={r['reported_at']}, found {len(window_acts)} deletion activities in window")
    if window_acts:
        matched_count += 1

print(f"\nTotal sample requests matched: {matched_count}/{len(sample_reqs)}")
