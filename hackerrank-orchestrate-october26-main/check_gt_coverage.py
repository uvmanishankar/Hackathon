import json, csv
from build_observations import observations as base_obs
from scratch_log_parser import log_observations

combined_obs = base_obs + log_observations
print(f"Total combined observations: {len(combined_obs)}")

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_gt = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

all_gt_res = set()
for stat, steps in sample_gt.values():
    for s in steps:
        all_gt_res.add(s["resource_id"])

obs_res = {o["resource_id"] for o in combined_obs}
overlap = all_gt_res & obs_res
print(f"Combined coverage of GT resources: {len(overlap)}/{len(all_gt_res)} ({len(overlap)/len(all_gt_res)*100:.1f}%)")

missing = all_gt_res - obs_res
print(f"Missing GT resources: {len(missing)}")
for r in sorted(missing):
    print("  Missing:", r)
