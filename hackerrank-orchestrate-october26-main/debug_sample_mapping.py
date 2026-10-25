"""
Debug Sample Mapping - Deep analysis of how sample output derives from evidence and activities.
"""

import csv
import json
from datetime import datetime
from build_observations import observations

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_out = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

with open("dataset/system_activity.csv", encoding="utf-8") as f:
    acts = list(csv.DictReader(f))

# Let's inspect case_01 to case_08
for r in sample_reqs[:8]:
    cid = r["case_id"]
    status, steps = sample_out[cid]
    print(f"\n==========================================")
    print(f"CASE: {cid} ({status}) email={r['email']}")
    print(f"Requested: {r['requested_at']}, Reported: {r['reported_at']}, Audit: {r['audit_at']}")
    print(f"Target steps in ground truth ({len(steps)}):")
    for s in steps:
        print(f"   [{s['phase']:12s}] {s['system_id']:20s} {s['resource_id']:18s} {s['operation']:26s} -> {s['state']:10s} ev='{s['evidence_id']}'")
    
    # Check all activities matching resource_ids in steps
    step_rids = {s['resource_id'] for s in steps}
    print("Relevant activities for these resources:")
    for a in acts:
        if a['resource_id'] in step_rids:
            print(f"   act: {a['activity_id']} {a['event_time']} {a['event_type']} {a['resource_id']} res={a['reported_result']} details={a['details']}")

    # Check observations matching these resource_ids
    print("Relevant observations for these resources:")
    for o in observations:
        if o['resource_id'] in step_rids:
            print(f"   obs: ev={o['evidence_id']} cap={o['captured_at']} sys={o['system_id']} res={o['resource_id']} st={o['state']}")
