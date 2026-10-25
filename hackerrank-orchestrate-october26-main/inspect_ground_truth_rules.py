import csv, json
from datetime import datetime

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_gt = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    acts = list(csv.DictReader(f))

from build_observations import observations

for r in sample_reqs:
    cid = r["case_id"]
    status, steps = sample_gt[cid]
    print(f"\n=== {cid} ({status}) ===")
    for s in steps:
        rid = s["resource_id"]
        # Find activities
        matching_acts = [a for a in acts if a["resource_id"] == rid]
        act_info = [f"{a['activity_id']}:{a['event_type']}:{a['reported_result']}" for a in matching_acts]
        # Find observations
        matching_obs = [o for o in observations if o["resource_id"] == rid]
        obs_info = [f"{o['evidence_id']}:{o['state']}" for o in matching_obs]
        print(f"  {s['phase']:12s} {s['system_id']:20s} {rid:18s} {s['operation']:26s} -> {s['state']:10s} ev='{s['evidence_id']}'")
        print(f"       acts: {act_info}")
        print(f"       obs:  {obs_info}")
