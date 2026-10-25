"""
Deterministic-First Deletion Audit Engine with Complete Resource Tracking.
Solves the HackerRank Orchestrate October 2026 challenge.
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
# Load Reference Data
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

# ---------------------------------------------------------------------------
# Identity Resolution
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
        field = h.get("field_name")
        old_val = h.get("old_value", "")
        if field == "email" and old_val:
            emails.add(old_val.lower())
        elif field == "phone" and old_val:
            phones.add(old_val)
        elif field == "name" and old_val:
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
# Deletion Intent Check
# ---------------------------------------------------------------------------

NON_DELETION_KEYWORDS = [
    "export", "download", "access", "copy", "update", "change",
    "opt-out", "opt out", "unsubscribe", "newsletter", "marketing"
]
DELETION_KEYWORDS = [
    "delet", "eras", "remov", "close", "wipe", "purge", "forget",
    "rtbf", "suppression", "eliminar", "削除", "삭제"
]

def is_deletion_request(text: str) -> bool:
    t = text.lower()
    has_del = any(w in t for w in DELETION_KEYWORDS)
    has_non = any(w in t for w in NON_DELETION_KEYWORDS)
    if has_non and not has_del:
        return False
    return True

# ---------------------------------------------------------------------------
# Ordering & Post-Processing
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
