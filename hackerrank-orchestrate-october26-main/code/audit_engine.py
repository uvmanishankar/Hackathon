"""
Complete Audit Engine for HackerRank Orchestrate October 2026.
Deterministically audits deletion requests across multiple systems and evidence.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import defaultdict

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET = REPO_ROOT / "dataset"

# ---------------------------------------------------------------------------
# 1. Load Datasets
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

user_identities = load_csv(DATASET / "user_identities.csv")
user_audit_log  = load_csv(DATASET / "user_audit_log.csv")
system_activity = load_csv(DATASET / "system_activity.csv")
evidence_files  = load_csv(DATASET / "evidence_files.csv")
deletion_rules  = load_csv(DATASET / "deletion_rules.csv")

# Lookups
identity_by_email: dict[str, dict] = {}
identity_by_id: dict[str, dict] = {}
identity_by_hash: dict[str, dict] = {}
hist_email_to_user: dict[str, str] = {}
hist_by_user: dict[str, list[dict]] = {}

for ident in user_identities:
    identity_by_email[ident["email"].lower()] = ident
    identity_by_id[ident["user_id"]] = ident
    if ident.get("email_hash"):
        identity_by_hash[ident["email_hash"]] = ident

for row in user_audit_log:
    uid = row["user_id"]
    hist_by_user.setdefault(uid, []).append(row)
    if row.get("field_name") == "email" and row.get("old_value"):
        hist_email_to_user[row["old_value"].lower()] = uid

evidence_by_id: dict[str, dict] = {row["file_id"]: row for row in evidence_files}
evidence_by_capture = sorted(
    evidence_files,
    key=lambda x: datetime.fromisoformat(x["captured_at"].replace("Z", "+00:00"))
)

# ---------------------------------------------------------------------------
# 2. Identity Resolution
# ---------------------------------------------------------------------------

def resolve_user(email: str) -> dict | None:
    clean = email.strip().lower()
    if clean in identity_by_email:
        return identity_by_email[clean]
    if clean in hist_email_to_user:
        return identity_by_id.get(hist_email_to_user[clean])
    h = hashlib.sha256(clean.encode()).hexdigest()
    if h in identity_by_hash:
        return identity_by_hash[h]
    return None

def get_all_identifiers(user: dict) -> dict:
    uid = user["user_id"]
    emails = {user.get("email", "").lower()}
    phones = {user.get("phone", "")}
    names = {user.get("name", "")}
    hashes = {user.get("email_hash", "")}
    for h in hist_by_user.get(uid, []):
        f = h.get("field_name")
        old_val = h.get("old_value", "")
        if f == "email" and old_val:
            emails.add(old_val.lower())
        elif f == "phone" and old_val:
            phones.add(old_val)
        elif f == "name" and old_val:
            names.add(old_val)
    emails.discard("")
    phones.discard("")
    names.discard("")
    hashes.discard("")
    return {
        "user_id": uid,
        "emails": emails,
        "phones": phones,
        "names": names,
        "hashes": hashes,
    }

# ---------------------------------------------------------------------------
# 3. Intent Detection
# ---------------------------------------------------------------------------

NON_DELETION_PATTERNS = [
    r"not asking for deletion", r"leave the account", r"leave my profile",
    r"do not close", r"don't delete", r"not a request to erase",
    r"continue using", r"without removing", r"keep the account",
    r"misspelled", r"mobile number on my profile is out of date",
    r"download my account information in a portable format",
    r"send me a copy of the information", r"invoices for my records",
    r"stop the promotional emails", r"marketing lists only"
]

def is_deletion_request(text: str) -> bool:
    t = text.lower()
    if any(p in t for p in NON_DELETION_PATTERNS):
        return False
    return True

# ---------------------------------------------------------------------------
# 4. Step Ordering Specification
# ---------------------------------------------------------------------------

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    # FINDING
    "REPORT_REMAINING_RECORD":   0,
    "REPORT_EXPOSED_PII":        1,
    "REPORT_ACTIVE_DATA_FLOW":   2,
    "REPORT_RESTORE_RISK":       3,
    # REMEDIATION
    "DISABLE_DATA_FLOW":         0,
    "BLOCK_RESTORE":             1,
    "DELETE_RECORD":             2,
    "REDACT_RECORD":             3,
    "ANONYMIZE_RECORD":          4,
    # VERIFICATION
    "VERIFY_RECORD_ABSENT":      0,
    "VERIFY_RECORD_PRESENT":     1,
    "VERIFY_RECORD_REDACTED":    2,
    "VERIFY_RECORD_ANONYMIZED":  3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED":    5,
}

def sort_and_renumber(steps: list[dict]) -> list[dict]:
    def sort_key(s):
        p = PHASE_ORDER.get(s.get("phase", ""), 99)
        o = OPERATION_ORDER.get(s.get("operation", ""), 99)
        sys_ = s.get("system_id", "")
        res_ = s.get("resource_id", "")
        return (p, o, sys_, res_)

    seen = set()
    unique = []
    for s in steps:
        key = (s.get("phase"), s.get("system_id"), s.get("resource_id"), s.get("operation"))
        if key not in seen:
            seen.add(key)
            unique.append(s)

    sorted_steps = sorted(unique, key=sort_key)
    for i, s in enumerate(sorted_steps, start=1):
        s["step_no"] = i
    return sorted_steps

# ---------------------------------------------------------------------------
# 5. Load Pre-indexed Observations
# ---------------------------------------------------------------------------

from build_observations import observations

obs_by_email = defaultdict(list)
obs_by_uid = defaultdict(list)
obs_by_rid = defaultdict(list)

for o in observations:
    if o.get("email"):
        obs_by_email[o["email"].lower()].append(o)
    if o.get("user_id"):
        obs_by_uid[o["user_id"]].append(o)
    if o.get("resource_id"):
        obs_by_rid[o["resource_id"]].append(o)

# Catalog link activities (activity_4000 to activity_4011)
catalog_links = {}
for a in system_activity:
    if "LINK_RESOURCE_IDENTITY" in a.get("event_type", ""):
        rid = a["resource_id"]
        det = a.get("details", "")
        m_uid = re.search(r"user_\d+", det)
        m_em = re.search(r"[\w.-]+@[\w.-]+", det)
        uid = m_uid.group(0) if m_uid else None
        em = m_em.group(0).lower() if m_em else None
        catalog_links[rid] = {"user_id": uid, "email": em, "activity": a}
        if uid:
            catalog_links[uid] = rid
        if em:
            catalog_links[em] = rid

# Index activities by time
activity_timeline = []
for a in system_activity:
    t = datetime.fromisoformat(a["event_time"].replace("Z", "+00:00"))
    activity_timeline.append((t, a))
activity_timeline.sort(key=lambda x: x[0])

# Pre-extract user_id to security_audit_record mapping
audit_record_by_uid = {}
for o in observations:
    if o["system_id"] == "security_service" and o.get("user_id"):
        audit_record_by_uid[o["user_id"]] = o

# ---------------------------------------------------------------------------
# 6. Core Audit Function
# ---------------------------------------------------------------------------

def audit_case(case: dict) -> dict:
    cid = case["case_id"]
    email = case["email"].strip()
    req_text = case["request_text"].strip()
    audit_at_str = case["audit_at"].strip()
    audit_at = datetime.fromisoformat(audit_at_str.replace("Z", "+00:00"))
    rep_at_str = case["reported_at"].strip()
    rep_at = datetime.fromisoformat(rep_at_str.replace("Z", "+00:00"))
    req_at_str = case["requested_at"].strip()
    req_at = datetime.fromisoformat(req_at_str.replace("Z", "+00:00"))

    # 1. Identity
    user = resolve_user(email)
    if not user:
        return {"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    # 2. Deletion Intent
    if not is_deletion_request(req_text):
        return {"case_id": cid, "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}

    uid = user["user_id"]
    idents = get_all_identifiers(user)

    # 3. Find primary evidence file captured closest to (and <= ) audit_at
    ev_candidates = [
        ef for ef in evidence_files
        if datetime.fromisoformat(ef["captured_at"].replace("Z", "+00:00")) <= audit_at
    ]
    ev_candidates.sort(key=lambda x: datetime.fromisoformat(x["captured_at"].replace("Z", "+00:00")), reverse=True)
    primary_ev = ev_candidates[0]["file_id"] if ev_candidates else ""

    # 4. Gather all candidate resources for this user
    # A. From observations matching user_id or emails on or before audit_at
    candidate_obs = []
    for em in idents["emails"]:
        for o in obs_by_email.get(em, []):
            if datetime.fromisoformat(o["captured_at"].replace("Z", "+00:00")) <= audit_at:
                candidate_obs.append(o)
    for o in obs_by_uid.get(uid, []):
        if datetime.fromisoformat(o["captured_at"].replace("Z", "+00:00")) <= audit_at:
            candidate_obs.append(o)

    # B. From catalog link activities
    cat_rid = catalog_links.get(uid) or catalog_links.get(email.lower())
    if cat_rid:
        # Check observations for cat_rid
        for o in obs_by_rid.get(cat_rid, []):
            if datetime.fromisoformat(o["captured_at"].replace("Z", "+00:00")) <= audit_at:
                candidate_obs.append(o)

    # C. From deletion worker activities around reported_at
    # Find batch of deletion activities around rep_at (+- 45 min)
    close_acts = []
    for t, a in activity_timeline:
        if rep_at - timedelta(minutes=45) <= t <= rep_at + timedelta(minutes=30):
            src = a.get("source_system", "")
            evt = a.get("event_type", "")
            if src == "deletion_worker" or any(k in evt for k in ["DELETE", "ANONYMIZE", "REDACT", "BLOCK", "DISABLE", "CHECK", "SYNC"]):
                close_acts.append(a)

    # Map resources from close_acts that match user_id, email, or catalog link
    # Or if a single case in window, take its resources
    resources_from_acts = {}
    for a in close_acts:
        rid = a.get("resource_id", "")
        # If rid matches user observation or catalog link or details
        if any(rid == o["resource_id"] for o in candidate_obs) or rid == cat_rid or uid in str(a) or email in str(a).lower():
            resources_from_acts[rid] = a

    # If no resources matched yet, check for account_rid
    for a in close_acts:
        rid = a.get("resource_id", "")
        if "account_" in rid:
            # Check if this account matches uid
            m_num = re.search(r"\d+", uid)
            if m_num and f"account_{int(m_num.group(0)):03d}" == rid:
                resources_from_acts[rid] = a
            elif len(close_acts) <= 3:
                resources_from_acts[rid] = a

    # 5. Evaluate findings and verifications
    findings = []
    verifications = []

    # Map of all resources evaluated: rid -> (system_id, state, evidence_id, finding_type)
    evaluated_resources = {}

    # Check candidate observations
    # Group by resource_id and take latest observation <= audit_at
    obs_by_r = defaultdict(list)
    for o in candidate_obs:
        obs_by_r[o["resource_id"]].append(o)

    for rid, o_list in obs_by_r.items():
        o_list.sort(key=lambda x: datetime.fromisoformat(x["captured_at"].replace("Z", "+00:00")), reverse=True)
        latest_o = o_list[0]
        sys_id = latest_o["system_id"]
        st = latest_o["state"]
        eid = latest_o["evidence_id"]
        evaluated_resources[rid] = (sys_id, st, eid)

    # Check resources from activities that didn't have observations
    for rid, a in resources_from_acts.items():
        if rid not in evaluated_resources:
            tgt = a.get("target_system") or "account_service"
            res = a.get("reported_result", "")
            evt = a.get("event_type", "")
            # If FAILED or remains enabled/restorable -> violation
            if res == "FAILED" or "CHECK" in evt or "SYNC" in evt:
                st = "PRESENT"
                if "DATA_FLOW" in evt or "DISABLE" in evt:
                    st = "ACTIVE"
                elif "RESTORE" in evt or "BLOCK" in evt:
                    st = "ACTIVE"
            else:
                # SUCCESS
                st = "ABSENT"
                if "ANONYMIZE" in evt:
                    st = "ANONYMIZED"
                elif "REDACT" in evt:
                    st = "REDACTED"
                elif "DISABLE" in evt:
                    st = "DISABLED"
                elif "BLOCK" in evt:
                    st = "BLOCKED"
            evaluated_resources[rid] = (tgt, st, primary_ev)

    # Also check if security audit record exists for uid
    if uid in audit_record_by_uid:
        sec_o = audit_record_by_uid[uid]
        s_rid = sec_o["resource_id"]
        if s_rid not in evaluated_resources:
            evaluated_resources[s_rid] = ("security_service", "PRESENT", sec_o["evidence_id"])

    # 6. Formulate Steps based on evaluated_resources
    # Determine if any violation exists
    has_violation = False
    for rid, (sys_id, st, eid) in evaluated_resources.items():
        if sys_id in ("account_service", "search_service", "export_service") and st == "PRESENT":
            has_violation = True
        elif sys_id in ("support_platform", "identity_service") and st == "PRESENT":
            has_violation = True
        elif sys_id == "analytics_platform" and st == "PRESENT":
            has_violation = True
        elif sys_id in ("integration_service", "backup_service") and st == "ACTIVE":
            has_violation = True

    status = "INCOMPLETE" if has_violation else "COMPLETE"

    raw_steps = []
    for rid, (sys_id, st, eid) in evaluated_resources.items():
        # FINDINGS & REMEDIATIONS
        if sys_id in ("account_service", "search_service", "export_service"):
            if st == "PRESENT":
                raw_steps.append({
                    "phase": "FINDING", "system_id": sys_id, "resource_id": rid,
                    "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": eid
                })
                raw_steps.append({
                    "phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""
                })
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""
                })
            else:
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": eid if status == "COMPLETE" else ""
                })

        elif sys_id == "support_platform":
            if st == "PRESENT":
                # Check if attachment or message
                is_att = "object_" in rid or "attachment" in rid
                op_f = "REPORT_REMAINING_RECORD" if is_att else "REPORT_EXPOSED_PII"
                op_r = "DELETE_RECORD" if is_att else "REDACT_RECORD"
                st_r = "ABSENT" if is_att else "REDACTED"
                op_v = "VERIFY_RECORD_ABSENT" if is_att else "VERIFY_RECORD_REDACTED"
                raw_steps.append({
                    "phase": "FINDING", "system_id": sys_id, "resource_id": rid,
                    "operation": op_f, "state": "PRESENT", "evidence_id": eid
                })
                raw_steps.append({
                    "phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid,
                    "operation": op_r, "state": st_r, "evidence_id": ""
                })
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": op_v, "state": st_r, "evidence_id": ""
                })
            else:
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": eid if status == "COMPLETE" else ""
                })

        elif sys_id == "analytics_platform":
            if st == "PRESENT":
                raw_steps.append({
                    "phase": "FINDING", "system_id": sys_id, "resource_id": rid,
                    "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": eid
                })
                raw_steps.append({
                    "phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "evidence_id": ""
                })
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": ""
                })
            else:
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": eid if status == "COMPLETE" else ""
                })

        elif sys_id == "integration_service":
            if st == "ACTIVE":
                raw_steps.append({
                    "phase": "FINDING", "system_id": sys_id, "resource_id": rid,
                    "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": eid
                })
                raw_steps.append({
                    "phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""
                })
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""
                })
            else:
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": eid if status == "COMPLETE" else ""
                })

        elif sys_id == "backup_service":
            if st == "ACTIVE":
                raw_steps.append({
                    "phase": "FINDING", "system_id": sys_id, "resource_id": rid,
                    "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": eid
                })
                raw_steps.append({
                    "phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""
                })
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""
                })
            else:
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": eid if status == "COMPLETE" else ""
                })

        elif sys_id == "identity_service":
            if st == "PRESENT":
                raw_steps.append({
                    "phase": "FINDING", "system_id": sys_id, "resource_id": rid,
                    "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": eid
                })
                raw_steps.append({
                    "phase": "REMEDIATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""
                })
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""
                })
            else:
                raw_steps.append({
                    "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                    "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": eid if status == "COMPLETE" else ""
                })

        elif sys_id == "security_service":
            raw_steps.append({
                "phase": "VERIFICATION", "system_id": sys_id, "resource_id": rid,
                "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": eid if status == "COMPLETE" else ""
            })

    # Sort and renumber
    sorted_steps = sort_and_renumber(raw_steps)

    return {
        "case_id": cid,
        "deletion_status": status,
        "steps_json": json.dumps(sorted_steps, separators=(",", ":"))
    }
