"""
Full Solver & Validator for Sample Cases
"""

import csv
import json
from datetime import datetime, timedelta
from build_observations import observations
from audit_engine import (
    resolve_user, get_all_identifiers, is_deletion_request,
    sort_and_renumber, evidence_files, evidence_by_id,
    system_activity
)

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_gt = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

# Build index of observations
obs_by_email = {}
obs_by_uid = {}
for o in observations:
    if o.get("email"):
        obs_by_email.setdefault(o["email"].lower(), []).append(o)
    if o.get("user_id"):
        obs_by_uid.setdefault(o["user_id"], []).append(o)

# Catalog link activities (activity_4000 to 4011)
catalog_links = {}
for a in system_activity:
    if "LINK_RESOURCE_IDENTITY" in a["event_type"]:
        rid = a["resource_id"]
        det = a["details"]
        # extract user_id and email if present
        m_uid = re.search(r"user_\d+", det)
        m_em = re.search(r"[\w.-]+@[\w.-]+", det)
        uid = m_uid.group(0) if m_uid else None
        em = m_em.group(0).lower() if m_em else None
        catalog_links[rid] = {"user_id": uid, "email": em, "activity": a}

print(f"Catalog links indexed: {len(catalog_links)}")
