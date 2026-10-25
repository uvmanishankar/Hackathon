"""
Correlate every deletion request to its deletion worker activity batch
"""

import csv
from datetime import datetime, timedelta
from collections import defaultdict

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/deletion_requests.csv", encoding="utf-8") as f:
    full_reqs = list(csv.DictReader(f))

all_reqs = sample_reqs + full_reqs

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    acts = list(csv.DictReader(f))

del_acts = [a for a in acts if any(w in a["event_type"] for w in ["DELETE", "ANONYMIZE", "REDACT", "DISABLE", "BLOCK"])]
print(f"Total requests: {len(all_reqs)}, Total deletion activities: {len(del_acts)}")

# Check how close each activity is to a reported_at timestamp
req_by_rep_time = defaultdict(list)
for r in all_reqs:
    rep_dt = datetime.fromisoformat(r["reported_at"].replace("Z", "+00:00"))
    req_by_rep_time[rep_dt].append(r)

print(f"Distinct reported_at timestamps across all 550 requests: {len(req_by_rep_time)}")

# Check distance from each activity to nearest reported_at
distances = []
for a in del_acts:
    act_dt = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
    min_dist = min(abs((act_dt - rep_dt).total_seconds()) for rep_dt in req_by_rep_time.keys())
    distances.append(min_dist)

within_15m = sum(1 for d in distances if d <= 900)
within_1h  = sum(1 for d in distances if d <= 3600)
within_2h  = sum(1 for d in distances if d <= 7200)

print(f"Activities within 15 min of a reported_at: {within_15m}/{len(del_acts)} ({within_15m/len(del_acts):.1%})")
print(f"Activities within 1 hour of a reported_at:   {within_1h}/{len(del_acts)} ({within_1h/len(del_acts):.1%})")
print(f"Activities within 2 hours of a reported_at:  {within_2h}/{len(del_acts)} ({within_2h/len(del_acts):.1%})")
