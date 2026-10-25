"""
Unified Evidence Parser across JSON, SQL, and Logs.
Extracts observations from all 94 evidence files.
"""

import csv
import json
import re
import sqlite3
from pathlib import Path

DATASET = Path("dataset")

with open(DATASET / "evidence_files.csv", encoding="utf-8") as f:
    ev_files = list(csv.DictReader(f))

observations = []

# ---------------------------------------------------------------------------
# 1. Parse JSON files
# ---------------------------------------------------------------------------
for ef in ev_files:
    if not ef["file_path"].endswith(".json"):
        continue
    p = DATASET / ef["file_path"]
    if not p.exists():
        continue
    fid = ef["file_id"]
    cap = ef["captured_at"]
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        continue

    # service_resource_export
    if "service_exports" in data:
        se = data["service_exports"]
        for item in se.get("account_service", {}).get("profile_lookups", []):
            rid = item.get("resource_id")
            sc = item.get("status_code")
            prof = item.get("profile") or {}
            em = prof.get("email")
            uid = prof.get("customer_reference")
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "account_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "ABSENT" if sc == 404 else "PRESENT",
            })
        for item in se.get("analytics_platform", {}).get("profiles", []):
            rid = item.get("resource_id")
            em = item.get("email")
            uid = item.get("customer_reference")
            is_anon = not (em or item.get("phone") or item.get("email_hash"))
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "analytics_platform",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "ANONYMIZED" if is_anon else "PRESENT",
            })
        for item in se.get("backup_service", {}).get("restore_entries", []):
            rid = item.get("resource_id")
            uid = item.get("customer_reference")
            em = item.get("customer_email")
            rest_ok = item.get("restore_allowed", False)
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "backup_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "ACTIVE" if rest_ok else "BLOCKED",
            })
        for item in se.get("export_service", {}).get("exports", []):
            rid = item.get("resource_id")
            em = item.get("owner_email")
            uid = item.get("customer_reference")
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "export_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "PRESENT",
            })
        for item in se.get("integration_service", {}).get("connectors", []):
            rid = item.get("resource_id")
            uid = item.get("customer_reference")
            em = item.get("customer_email")
            en = item.get("enabled", False)
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "integration_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "ACTIVE" if en else "DISABLED",
            })
        for item in se.get("search_service", {}).get("index_queries", []):
            rid = item.get("resource_id")
            hits = item.get("hits", {})
            total = hits.get("total", 0)
            docs = hits.get("documents", [])
            em = item.get("query")
            uid = None
            if docs:
                em = docs[0].get("email") or em
                uid = docs[0].get("customer_reference")
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "search_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "PRESENT" if total > 0 else "ABSENT",
            })
        for item in se.get("support_platform", {}).get("support_tickets", []):
            rid = item.get("resource_id")
            em = item.get("requester_email")
            uid = item.get("customer_reference")
            is_redacted = not (em or item.get("requester_name") or item.get("requester_phone"))
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "support_platform",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "REDACTED" if is_redacted else "PRESENT",
            })
        for item in se.get("security_service", {}).get("audit_records", []):
            rid = item.get("resource_id")
            uid = item.get("subject_reference")
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "security_service",
                "resource_id": rid, "user_id": uid, "email": None,
                "state": "PRESENT",
            })

    # customer_data_snapshot_bundle
    if "snapshots" in data:
        for snap in data["snapshots"]:
            ds = snap.get("data_store")
            for rec in snap.get("records", []):
                rid = rec.get("resource_id")
                uid = rec.get("subject_reference") or rec.get("customer_reference")
                em = rec.get("email")
                if ds == "identity_service":
                    has_pii = bool(em or rec.get("name") or rec.get("phone") or rec.get("email_hash"))
                    observations.append({
                        "evidence_id": fid, "captured_at": cap, "system_id": "identity_service",
                        "resource_id": rid, "user_id": uid, "email": em,
                        "state": "PRESENT" if has_pii else "REDACTED",
                    })
                elif ds == "security_service":
                    observations.append({
                        "evidence_id": fid, "captured_at": cap, "system_id": "security_service",
                        "resource_id": rid, "user_id": uid, "email": None,
                        "state": "PRESENT",
                    })
                elif ds == "account_service":
                    observations.append({
                        "evidence_id": fid, "captured_at": cap, "system_id": "account_service",
                        "resource_id": rid, "user_id": uid, "email": em,
                        "state": "PRESENT",
                    })

    # customer_analytics_report
    if "profiles" in data and isinstance(data["profiles"], list):
        for prof in data["profiles"]:
            rid = prof.get("resource_id")
            em = prof.get("email")
            uid = prof.get("customer_reference")
            is_anon = not (em or prof.get("phone") or prof.get("email_hash"))
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "analytics_platform",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "ANONYMIZED" if is_anon else "PRESENT",
            })

    # customer_export_jobs
    if "jobs" in data and isinstance(data["jobs"], list):
        for job in data["jobs"]:
            rid = job.get("resource_id")
            em = job.get("customer_email") or job.get("owner_email")
            uid = job.get("customer_reference")
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "export_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "PRESENT",
            })

    # connector_configurations
    if "connectors" in data and isinstance(data["connectors"], list):
        for conn in data["connectors"]:
            rid = conn.get("resource_id")
            em = conn.get("customer_email") or conn.get("subject_selector")
            uid = conn.get("customer_reference")
            en = conn.get("enabled", False)
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "integration_service",
                "resource_id": rid, "user_id": uid, "email": em,
                "state": "ACTIVE" if en else "DISABLED",
            })

    # security_audit_ledger
    if "audit_ledger" in data and isinstance(data["audit_ledger"], list):
        for rec in data["audit_ledger"]:
            rid = rec.get("resource_id")
            uid = rec.get("subject_reference") or rec.get("user_id")
            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": "security_service",
                "resource_id": rid, "user_id": uid, "email": None,
                "state": "PRESENT",
            })

# ---------------------------------------------------------------------------
# 2. Parse SQL files via SQLite
# ---------------------------------------------------------------------------
for ef in ev_files:
    if not ef["file_path"].endswith(".sql"):
        continue
    p = DATASET / ef["file_path"]
    if not p.exists():
        continue
    fid = ef["file_id"]
    cap = ef["captured_at"]
    txt = p.read_text(encoding="utf-8")
    try:
        conn = sqlite3.connect(":memory:")
        conn.executescript(txt)
    except Exception:
        continue

    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for t in tables:
        t_low = t.lower()
        rows = conn.execute(f"SELECT * FROM [{t}]").fetchall()
        cols = [d[0] for d in conn.execute(f"SELECT * FROM [{t}] LIMIT 0").description]
        
        # Generic replica tables with JSON payloads
        if any(w in t_low for w in ["customer_data_primary", "customer_data_read_replica", "customer_data_replica", "customer_data_reporting", "customer_data_failover"]):
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                sys_id = r_dict.get("service_name") or r_dict.get("origin_system")
                payload_str = r_dict.get("record_json") or r_dict.get("json_payload") or r_dict.get("payload") or r_dict.get("record_data")
                if payload_str and isinstance(payload_str, str):
                    try:
                        p_data = json.loads(payload_str)
                    except Exception:
                        p_data = {}
                elif isinstance(payload_str, dict):
                    p_data = payload_str
                else:
                    p_data = {}

                uid = p_data.get("user_id") or p_data.get("customer_reference") or p_data.get("subject_reference")
                em = p_data.get("email") or p_data.get("owner_email") or p_data.get("customer_email") or p_data.get("subject_selector")
                doc = p_data.get("document")
                if isinstance(doc, dict):
                    em = em or doc.get("email")
                    uid = uid or doc.get("customer_reference")

                st = "PRESENT"
                if sys_id == "analytics_platform":
                    is_anon = not (em or p_data.get("phone") or p_data.get("email_hash"))
                    st = "ANONYMIZED" if is_anon else "PRESENT"
                elif sys_id == "integration_service":
                    en = p_data.get("enabled", True)
                    st = "ACTIVE" if en in (True, "true", 1, "1") else "DISABLED"
                elif sys_id == "backup_service":
                    rest_ok = p_data.get("restore_allowed", True)
                    st = "ACTIVE" if rest_ok in (True, "true", 1, "1") else "BLOCKED"
                elif sys_id == "support_platform":
                    has_id = bool(em or p_data.get("requester_name") or p_data.get("requester_phone"))
                    st = "PRESENT" if has_id else "REDACTED"

                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": sys_id,
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": st,
                })

        elif "customer_profiles" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("user_id") or r_dict.get("customer_reference")
                em = r_dict.get("email")
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "account_service",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "PRESENT",
                })
        elif "search" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("customer_reference")
                em = r_dict.get("email")
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "search_service",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "PRESENT",
                })
        elif "analytic" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("customer_reference")
                em = r_dict.get("email")
                is_anon = not (em or r_dict.get("phone") or r_dict.get("email_hash"))
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "analytics_platform",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "ANONYMIZED" if is_anon else "PRESENT",
                })
        elif "backup" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("customer_reference")
                em = r_dict.get("customer_email")
                allowed = str(r_dict.get("restore_allowed", "0")) in ("1", "True", "true")
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "backup_service",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "ACTIVE" if allowed else "BLOCKED",
                })
        elif "connector" in t_low or "data_flow" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("customer_reference")
                em = r_dict.get("customer_email")
                en = str(r_dict.get("enabled", "0")) in ("1", "True", "true")
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "integration_service",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "ACTIVE" if en else "DISABLED",
                })
        elif "export" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("customer_reference")
                em = r_dict.get("owner_email")
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "export_service",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "PRESENT",
                })
        elif "support" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("customer_reference")
                em = r_dict.get("requester_email")
                is_redacted = not (em or r_dict.get("requester_name") or r_dict.get("requester_phone"))
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "support_platform",
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": "REDACTED" if is_redacted else "PRESENT",
                })
        elif "audit" in t_low:
            for row in rows:
                r_dict = dict(zip(cols, row))
                rid = r_dict.get("resource_id")
                uid = r_dict.get("subject_reference")
                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": "security_service",
                    "resource_id": rid, "user_id": uid, "email": None,
                    "state": "PRESENT",
                })

# ---------------------------------------------------------------------------
# 3. Parse Handover text & Logs
# ---------------------------------------------------------------------------
for ef in ev_files:
    fid = ef["file_id"]
    cap = ef["captured_at"]
    p = DATASET / ef["file_path"]
    if not p.exists():
        continue

    # Handover txt
    if ef["file_path"].endswith("customer_account_handover_20261001.txt"):
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line.startswith("- "):
                continue
            parts = [x.strip() for x in line[2:].split("|")]
            if len(parts) >= 6:
                ts, sys_id, rid, cat, status, target = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
                uid = target if target.startswith("user_") else None
                em = target if "@" in target else None
                st = "PRESENT"
                if status == "NOT_FOUND":
                    st = "ABSENT"
                elif status in ("ANONYMIZED",):
                    st = "ANONYMIZED"
                elif status in ("REDACTED",):
                    st = "REDACTED"
                elif status == "BLOCKED":
                    st = "BLOCKED"
                elif status == "ACTIVE":
                    st = "ACTIVE"
                elif status == "DISABLED":
                    st = "DISABLED"

                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": sys_id,
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": st,
                })

    # Readback logs
    elif "resource_lookup_trace" in ef["file_path"]:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if "event=" not in line or "resource_id=" not in line:
                continue
            kvs = {}
            for token in line.split():
                if "=" in token:
                    k, v = token.split("=", 1)
                    kvs[k] = v
            sys_id = kvs.get("service")
            rid = kvs.get("resource_id")
            evt = kvs.get("event")
            uid = kvs.get("customer_reference") or kvs.get("subject_reference")
            if uid == "null": uid = None
            em = kvs.get("lookup_key") if "@" in (kvs.get("lookup_key") or "") else (kvs.get("email") or kvs.get("customer_email") or kvs.get("requester_email"))
            if em == "null": em = None

            if "completed" in evt or "hit" in kvs.get("result", ""):
                st = "PRESENT"
                if kvs.get("http_status") == "404" or kvs.get("rows") == "0":
                    st = "ABSENT"
                elif sys_id == "analytics_platform":
                    is_anon = (kvs.get("email") in (None, "null")) and (kvs.get("phone") in (None, "null")) and (kvs.get("email_hash") in (None, "null"))
                    st = "ANONYMIZED" if is_anon else "PRESENT"
                elif sys_id == "backup_service":
                    st = "ACTIVE" if kvs.get("restore_allowed") == "true" else "BLOCKED"
                elif sys_id == "integration_service":
                    st = "ACTIVE" if kvs.get("enabled") == "true" else "DISABLED"
                elif sys_id == "support_platform":
                    has_id = (kvs.get("requester_email") not in (None, "null")) or (kvs.get("requester_name") not in (None, "null"))
                    st = "PRESENT" if has_id else "REDACTED"
                elif sys_id == "security_service":
                    st = "PRESENT"

                observations.append({
                    "evidence_id": fid, "captured_at": cap, "system_id": sys_id,
                    "resource_id": rid, "user_id": uid, "email": em,
                    "state": st,
                })

    # Structured JSON log lines
    elif "structured_service_events" in ef["file_path"] or "service_events" in ef["file_path"]:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            sys_id = rec.get("service")
            rid = rec.get("resource_id")
            if not rid or not sys_id:
                continue
            uid = rec.get("subject_ref") or rec.get("customer_reference")
            em = rec.get("lookup_key") if "@" in (rec.get("lookup_key") or "") else rec.get("email")
            evt = rec.get("event")
            st = "PRESENT"
            if rec.get("rows") == "0" or rec.get("status") == "not_found" or rec.get("http_status") == 404:
                st = "ABSENT"
            elif sys_id == "backup_service":
                st = "ACTIVE" if rec.get("restore_allowed") in (True, "true", 1, "1") else "BLOCKED"
            elif sys_id == "integration_service":
                st = "ACTIVE" if rec.get("enabled") in (True, "true", 1, "1") else "DISABLED"

            observations.append({
                "evidence_id": fid, "captured_at": cap, "system_id": sys_id,
                "resource_id": rid, "user_id": uid, "email": em,
                "state": st,
            })

print(f"Total unified observations extracted: {len(observations)}")
