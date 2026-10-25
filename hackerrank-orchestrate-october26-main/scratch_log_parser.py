import os
import re
import json
import csv
from datetime import datetime
from collections import defaultdict

with open("dataset/evidence_files.csv", encoding="utf-8") as f:
    ev_files = {r["file_path"].replace("\\", "/"): r for r in csv.DictReader(f)}

with open("dataset/user_identities.csv", encoding="utf-8") as f:
    identities = {r["email"].lower(): r for r in csv.DictReader(f)}
    id_by_uid = {r["user_id"]: r for r in identities.values()}

with open("dataset/user_audit_log.csv", encoding="utf-8") as f:
    for a in csv.DictReader(f):
        if a.get("field_name") == "email" and a.get("old_value"):
            identities[a["old_value"].lower()] = id_by_uid.get(a["user_id"])

log_observations = []

log_dir = "dataset/evidence/logs"
for fname in sorted(os.listdir(log_dir)):
    rel_path = f"evidence/logs/{fname}"
    ef = ev_files.get(rel_path)
    if not ef:
        continue
    fid = ef["file_id"]
    cap = ef["captured_at"]
    p = os.path.join(log_dir, fname)

    # We track trace_context per file
    trace_info = defaultdict(dict)
    file_lines = []

    with open(p, "r", encoding="utf-8", errors="ignore") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue

            # First check if line has JSON embedded (like structured_service_events or cloud_runtime message)
            json_match = re.search(r'(\{.*\})', line)
            kvs = {}
            if json_match:
                try:
                    payload = json.loads(json_match.group(1))
                    if isinstance(payload, dict):
                        # Flatten or extract message if message contains key=value
                        msg = payload.get("message", "")
                        if "event=" in msg or "resource_id=" in msg:
                            # parse message string
                            for k, v in re.findall(r'([a-zA-Z0-9_-]+)=["\']?([^"\'\s]+)', msg):
                                kvs[k] = v
                        for k, v in payload.items():
                            if k != "message":
                                kvs[k] = str(v)
                except Exception:
                    pass

            # Also extract standard key=value tokens
            for k, v in re.findall(r'([a-zA-Z0-9_-]+)=["\']?([^"\'\s]+)', line):
                if k not in kvs:
                    kvs[k] = v

            # Check trace_id or requestId
            tr = kvs.get("trace_id") or kvs.get("requestId")
            # Extract key/identity
            user_key = (
                kvs.get("lookup_key") or kvs.get("match_key") or kvs.get("owner_key")
                or kvs.get("subject_key") or kvs.get("correlation_key") or kvs.get("subject_ref")
                or kvs.get("subject_reference") or kvs.get("matched_value")
            )
            if user_key and tr:
                trace_info[tr]["user_key"] = user_key

            # If service is specified
            svc = kvs.get("service") or kvs.get("system") or kvs.get("logger")
            if svc and tr:
                trace_info[tr]["service"] = svc

            file_lines.append((line, kvs, tr))

    # Now process lines with trace context
    for line, kvs, tr in file_lines:
        rid = kvs.get("resource_id")
        evt = kvs.get("event") or ""
        svc = kvs.get("service") or kvs.get("system") or (trace_info[tr].get("service") if tr else None)
        user_key = (
            kvs.get("lookup_key") or kvs.get("match_key") or kvs.get("owner_key")
            or kvs.get("subject_key") or kvs.get("correlation_key") or kvs.get("subject_ref")
            or kvs.get("subject_reference") or kvs.get("matched_value")
            or (trace_info[tr].get("user_key") if tr else None)
        )

        if not rid:
            continue

        # Determine user_id and email from user_key
        uid = None
        em = None
        if user_key:
            user_key_clean = user_key.strip('"\'')
            if user_key_clean.startswith("user_"):
                uid = user_key_clean
            elif "@" in user_key_clean:
                em = user_key_clean
                u = identities.get(em.lower())
                if u: uid = u["user_id"]
            else:
                # Could be sha256 hash
                for ident in identities.values():
                    if ident.get("email_hash") == user_key_clean:
                        uid = ident["user_id"]
                        em = ident["email"]
                        break

        # Map service name to standard system_id
        sys_id = None
        if svc:
            if "account" in svc or "profile" in svc:
                sys_id = "account_service"
            elif "analytics" in svc:
                sys_id = "analytics_platform"
            elif "backup" in svc:
                sys_id = "backup_service"
            elif "export" in svc:
                sys_id = "export_service"
            elif "integration" in svc or "connector" in svc:
                sys_id = "integration_service"
            elif "search" in svc:
                sys_id = "search_service"
            elif "support" in svc:
                sys_id = "support_platform"
            elif "security" in svc:
                sys_id = "security_service"
            elif "identity" in svc:
                sys_id = "identity_service"

        if not sys_id:
            # Infer from resource_id prefix
            if rid.startswith("account_"): sys_id = "account_service"
            elif rid.startswith("analytics_"): sys_id = "analytics_platform"
            elif rid.startswith("backup_"): sys_id = "backup_service"
            elif rid.startswith("export_"): sys_id = "export_service"
            elif rid.startswith("data_flow_"): sys_id = "integration_service"
            elif rid.startswith("search_"): sys_id = "search_service"
            elif rid.startswith("support_"): sys_id = "support_platform"
            elif rid.startswith("audit_record_"): sys_id = "security_service"
            elif rid.startswith("tombstone_"): sys_id = "identity_service"

        # Determine state
        st = "PRESENT"
        res_str = (kvs.get("result") or "").lower()
        http_st = kvs.get("http_status")
        rows = kvs.get("rows")

        if http_st == "404" or rows == "0" or res_str == "not_found" or res_str == "miss":
            st = "ABSENT"
        elif sys_id == "account_service":
            st = "ABSENT" if (http_st == "404" or rows == "0") else "PRESENT"
        elif sys_id == "analytics_platform":
            # Check if anonymized
            dir_ids = kvs.get("direct_identifiers")
            em_val = kvs.get("email")
            ph_val = kvs.get("phone")
            opt_in = kvs.get("email_opt_in")
            if dir_ids == "0" or (em_val in (None, "null", "") and ph_val in (None, "null", "")):
                st = "ANONYMIZED"
            else:
                st = "PRESENT"
        elif sys_id == "backup_service":
            del_block = kvs.get("deletion_block")
            rest_allow = kvs.get("restore_allowed")
            if del_block in ("false", "0") or rest_allow in ("true", "1") or kvs.get("eligible") == "true":
                st = "ACTIVE"
            else:
                st = "BLOCKED"
        elif sys_id == "integration_service":
            en = kvs.get("enabled")
            sched = kvs.get("scheduler_registered")
            if en in ("true", "1") or sched in ("true", "1"):
                st = "ACTIVE"
            else:
                st = "DISABLED"
        elif sys_id == "support_platform":
            if "scan" in evt or "pii" in evt:
                st = "PRESENT"
            elif kvs.get("marker_found") == "false":
                st = "PRESENT"
            elif rows == "0":
                st = "ABSENT"
            else:
                st = "PRESENT"
        elif sys_id == "security_service":
            st = "PRESENT"

        log_observations.append({
            "evidence_id": fid,
            "captured_at": cap,
            "system_id": sys_id,
            "resource_id": rid,
            "user_id": uid,
            "email": em,
            "state": st,
            "event": evt
        })

print(f"Total new observations parsed from logs: {len(log_observations)}")

# Check overlap with sample ground truth
with open("dataset/sample_output.csv", encoding="utf-8") as f:
    sample_gt = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(f)}

with open("dataset/sample_deletion_requests.csv", encoding="utf-8") as f:
    sample_reqs = list(csv.DictReader(f))

# Count coverage of sample ground truth resources
all_gt_res = set()
for stat, steps in sample_gt.values():
    for s in steps:
        all_gt_res.add(s["resource_id"])

log_res = {o["resource_id"] for o in log_observations}
print(f"Total unique GT resources: {len(all_gt_res)}")
print(f"Total unique Log resources: {len(log_res)}")
print(f"Intersection: {len(all_gt_res & log_res)}/{len(all_gt_res)}")
