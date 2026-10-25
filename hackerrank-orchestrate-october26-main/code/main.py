"""
Ghost Data Still Exists — AI-powered deletion-audit agent.

Entry point: python code/main.py
Output:      output.csv (repository root)

Requires:
  pip install groq pandas python-dotenv

Environment variable:
  GROQ_API_KEY  — Groq API key
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
import time
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

# ---------------------------------------------------------------------------
# Optional .env loading
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Groq client
# ---------------------------------------------------------------------------
try:
    from groq import Groq
except ImportError:
    print("groq package not installed. Run: pip install groq", file=sys.stderr)
    sys.exit(1)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
if not GROQ_API_KEY:
    print("ERROR: GROQ_API_KEY environment variable is not set.", file=sys.stderr)
    sys.exit(1)

MODEL = "qwen/qwen3.8-27b"
client = Groq(api_key=GROQ_API_KEY)

# Pacing: free tier TPM limit varies. Sleep 8s between calls as a safe default.
# The retry logic will auto-wait longer if rate-limited.
CALL_DELAY_S = 8

# ---------------------------------------------------------------------------
# Path setup (all relative to repo root)
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
DATASET = REPO_ROOT / "dataset"
EVIDENCE_DIR = DATASET / "evidence"
OUTPUT_CSV = REPO_ROOT / "output.csv"

# ---------------------------------------------------------------------------
# Load all reference datasets into memory once
# ---------------------------------------------------------------------------

def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

print("Loading dataset files...")
deletion_requests  = load_csv(DATASET / "deletion_requests.csv")
deletion_rules     = load_csv(DATASET / "deletion_rules.csv")
user_identities    = load_csv(DATASET / "user_identities.csv")
user_audit_log     = load_csv(DATASET / "user_audit_log.csv")
system_activity    = load_csv(DATASET / "system_activity.csv")
evidence_files     = load_csv(DATASET / "evidence_files.csv")

# Pre-build lookup maps
identity_by_email: dict[str, dict] = {}  # normalised_email -> identity row
identity_by_id: dict[str, dict] = {}
identity_by_hash: dict[str, dict] = {}

for ident in user_identities:
    identity_by_email[ident["email"].lower()] = ident
    identity_by_id[ident["user_id"]] = ident
    if ident.get("email_hash"):
        identity_by_hash[ident["email_hash"]] = ident

# Historical identifiers: user_id -> list of old values per field
hist_by_user: dict[str, list[dict]] = {}
for row in user_audit_log:
    uid = row["user_id"]
    hist_by_user.setdefault(uid, []).append(row)

# Also index audit log by old email value so we can find users by historical email
hist_email_to_user: dict[str, str] = {}
for row in user_audit_log:
    if row["field_name"] == "email":
        hist_email_to_user[row["old_value"].lower()] = row["user_id"]

# Activity grouped by resource_id for fast lookup
activity_by_resource: dict[str, list[dict]] = {}
for row in system_activity:
    rid = row["resource_id"]
    activity_by_resource.setdefault(rid, []).append(row)

# Activity also indexed by event_type
activity_by_type: dict[str, list[dict]] = {}
for row in system_activity:
    etype = row["event_type"]
    activity_by_type.setdefault(etype, []).append(row)

# Evidence manifest indexed by file_id
evidence_by_id: dict[str, dict] = {row["file_id"]: row for row in evidence_files}

print(f"  {len(deletion_requests)} requests, {len(user_identities)} identities, "
      f"{len(system_activity)} activities, {len(evidence_files)} evidence files.")

# ---------------------------------------------------------------------------
# Evidence content cache -- read files lazily
# ---------------------------------------------------------------------------

_evidence_content_cache: dict[str, str] = {}

def read_evidence_file(file_id: str) -> str:
    """Return the text content of an evidence file (cached)."""
    if file_id in _evidence_content_cache:
        return _evidence_content_cache[file_id]
    meta = evidence_by_id.get(file_id)
    if not meta:
        return ""
    path = DATASET / meta["file_path"]
    if not path.exists():
        return ""
    suffix = path.suffix.lower()
    try:
        if suffix in (".txt", ".log", ".json", ".sql", ".csv", ".md"):
            content = path.read_text(encoding="utf-8", errors="replace")
        elif suffix == ".pdf":
            try:
                import pdfplumber
                with pdfplumber.open(path) as pdf:
                    content = "\n".join(
                        page.extract_text() or "" for page in pdf.pages
                    )
            except Exception:
                content = f"[PDF: {path.name} -- install pdfplumber to read]"
        elif suffix in (".png", ".jpg", ".jpeg", ".webp"):
            content = f"[Image: {path.name} -- visual evidence, cannot extract text]"
        else:
            content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        content = f"[Error reading {path.name}: {exc}]"
    # Truncate very large files to avoid context overflow
    if len(content) > 80_000:
        content = content[:80_000] + "\n...[truncated]"
    _evidence_content_cache[file_id] = content
    return content

# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------

def resolve_user(email: str) -> dict | None:
    """Return the identity row for the given email (current or historical)."""
    email_lower = email.lower().strip()
    if email_lower in identity_by_email:
        return identity_by_email[email_lower]
    if email_lower in hist_email_to_user:
        uid = hist_email_to_user[email_lower]
        return identity_by_id.get(uid)
    # Try email-hash match
    email_hash = hashlib.sha256(email_lower.encode()).hexdigest()
    if email_hash in identity_by_hash:
        return identity_by_hash[email_hash]
    return None

def get_all_identifiers(user: dict) -> dict:
    """Return all current + historical identifiers for a user."""
    uid = user["user_id"]
    result = {
        "user_id": uid,
        "current_email": user.get("email", ""),
        "current_name":  user.get("name", ""),
        "current_phone": user.get("phone", ""),
        "email_hash":    user.get("email_hash", ""),
        "historical": []
    }
    for row in hist_by_user.get(uid, []):
        result["historical"].append({
            "field": row["field_name"],
            "old_value": row["old_value"],
            "new_value": row["new_value"],
            "event_time": row["event_time"],
        })
    return result

# ---------------------------------------------------------------------------
# Activity filtering
# ---------------------------------------------------------------------------

def get_activities_for_user(user_id: str, identifiers: dict, audit_at: str) -> list[dict]:
    """Return system activities up to audit_at that likely concern the user."""
    audit_dt = datetime.fromisoformat(audit_at.replace("Z", "+00:00"))
    all_emails = {identifiers["current_email"].lower()}
    all_phones = {identifiers["current_phone"]}
    all_names  = {identifiers["current_name"]}
    for h in identifiers["historical"]:
        if h["field"] == "email":
            all_emails.add(h["old_value"].lower())
        elif h["field"] == "phone":
            all_phones.add(h["old_value"])
        elif h["field"] == "name":
            all_names.add(h["old_value"])

    relevant = []
    for row in system_activity:
        evt_time = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
        if evt_time > audit_dt:
            continue
        details = (row.get("details") or "").lower()
        rid     = (row.get("resource_id") or "").lower()
        matched = False
        for em in all_emails:
            if em and em in details:
                matched = True
                break
        if not matched:
            for ph in all_phones:
                if ph and ph in details:
                    matched = True
                    break
        if not matched:
            if user_id.lower() in details or user_id.lower() in rid:
                matched = True
        if matched:
            relevant.append(row)
    return relevant

# ---------------------------------------------------------------------------
# Evidence file relevance
# ---------------------------------------------------------------------------

def find_relevant_evidence(identifiers: dict, audit_at: str) -> list[tuple[str, str]]:
    """Return list of (file_id, truncated_content) for evidence captured <= audit_at."""
    audit_dt = datetime.fromisoformat(audit_at.replace("Z", "+00:00"))
    all_ids: set[str] = set()
    all_ids.add(identifiers["user_id"].lower())
    all_ids.add(identifiers["current_email"].lower())
    for h in identifiers["historical"]:
        all_ids.add(h["old_value"].lower())
    all_ids.discard("")

    results = []
    for ev in evidence_files:
        cap = datetime.fromisoformat(ev["captured_at"].replace("Z", "+00:00"))
        if cap > audit_dt:
            continue
        content = read_evidence_file(ev["file_id"])
        content_lower = content.lower()
        for ident in all_ids:
            if ident and ident in content_lower:
                idx = content_lower.find(ident)
                start = max(0, idx - 500)
                end   = min(len(content), idx + 3500)
                snippet = content[start:end]
                results.append((ev["file_id"], snippet))
                break
    return results

# ---------------------------------------------------------------------------
# Deletion intent detection (heuristic)
# ---------------------------------------------------------------------------

DELETION_KEYWORDS = [
    "delet", "erase", "remov", "close", "wipe", "purge", "forget",
    "right to be forgotten", "rtbf", "gdpr", "ccpa", "right erasure",
]
NON_DELETION_KEYWORDS = [
    "export", "download", "access", "correct", "update", "change",
    "opt.out", "unsubscribe", "marketing",
]

def quick_deletion_intent(request_text: str) -> bool | None:
    """Heuristic pre-check. Returns True=likely deletion, False=likely not, None=uncertain."""
    text_lower = request_text.lower()
    has_del = any(kw in text_lower for kw in DELETION_KEYWORDS)
    has_non = any(kw in text_lower for kw in NON_DELETION_KEYWORDS)
    if has_del and not has_non:
        return True
    if has_non and not has_del:
        return False
    return None

# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------

def call_llm(system_prompt: str, user_prompt: str, max_tokens: int = 1200) -> str:
    """Call Groq API with pacing and exponential backoff on rate-limit errors."""
    for attempt in range(8):
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                temperature=0,
                max_tokens=max_tokens,
            )
            # Pace between calls
            time.sleep(CALL_DELAY_S)
            return response.choices[0].message.content or ""
        except Exception as exc:
            msg = str(exc)
            if "429" in msg or "413" in msg or "rate_limit" in msg.lower():
                # Try to parse "try again in Xs" from error message
                m = re.search(r"try again in ([\d.]+)s", msg)
                wait = float(m.group(1)) + 2 if m else min(2 ** attempt * 5, 90)
                print(f" [TPM limit, waiting {wait:.0f}s]", end="", flush=True)
                time.sleep(wait)
            else:
                raise
    raise RuntimeError(f"Groq: exceeded retries on {MODEL}")

# ---------------------------------------------------------------------------
# Core audit logic
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_AUDIT = """Deletion audit agent. Output JSON only, no prose.

Deletion policy:
{rules}

Output schema:
{{"deletion_status":"COMPLETE"|"INCOMPLETE"|"NOT_APPLICABLE","steps":[{{"step_no":1,"phase":"FINDING"|"REMEDIATION"|"VERIFICATION","system_id":"...","resource_id":"...","operation":"...","state":"...","evidence_id":"..."}}]}}

Phase/operation/state pairs:
FINDING: REPORT_REMAINING_RECORD->PRESENT, REPORT_EXPOSED_PII->PRESENT, REPORT_ACTIVE_DATA_FLOW->ACTIVE, REPORT_RESTORE_RISK->ACTIVE
REMEDIATION: DISABLE_DATA_FLOW->DISABLED, BLOCK_RESTORE->BLOCKED, DELETE_RECORD->ABSENT, REDACT_RECORD->REDACTED, ANONYMIZE_RECORD->ANONYMIZED
VERIFICATION: VERIFY_RECORD_ABSENT->ABSENT, VERIFY_RECORD_PRESENT->PRESENT, VERIFY_RECORD_REDACTED->REDACTED, VERIFY_RECORD_ANONYMIZED->ANONYMIZED, VERIFY_DATA_FLOW_DISABLED->DISABLED, VERIFY_RESTORE_BLOCKED->BLOCKED

Rules:
- NOT_APPLICABLE if request_text is NOT a deletion request (access/export/marketing/correction = NOT_APPLICABLE).
- Resolve identifiers from USER IDENTITY section.
- TRUE state at audit_at from evidence only; ignore reported_status.
- Apply policy to every record in evidence.
- ACCOUNT_TOMBSTONE: REDACT name/email/phone/hash; keep user_id.
- SECURITY_AUDIT_LOG in retention -> RETAIN.
- BACKUP_ARCHIVE -> RETAIN + BLOCK_RESTORE.
- Order: FINDING->REMEDIATION->VERIFICATION; within phase sort by operation order above, then system_id, resource_id.
- COMPLETE: VERIFICATION steps only, each citing evidence_id.
- INCOMPLETE: FINDING steps cite evidence; REMEDIATION+future VERIFICATION use evidence_id="".
- Output ONLY the JSON object."""


def build_user_prompt(
    case: dict,
    identifiers: dict | None,
    activities: list[dict],
    evidence_snippets: list[tuple[str, str]],
) -> str:
    """Assemble the per-case prompt."""
    parts = []

    parts.append(f"=== CASE {case['case_id']} ===")
    parts.append(f"Email: {case['email']}")
    parts.append(f"Requested at: {case['requested_at']}")
    parts.append(f"Reported status: {case['reported_status']}")
    parts.append(f"Reported at: {case['reported_at']}")
    parts.append(f"Audit cutoff (audit_at): {case['audit_at']}")
    parts.append(f"Request text: {case['request_text']}")
    parts.append("")

    if identifiers:
        parts.append("=== USER IDENTITY ===")
        parts.append(f"user_id: {identifiers['user_id']}")
        parts.append(f"Current name:  {identifiers['current_name']}")
        parts.append(f"Current email: {identifiers['current_email']}")
        parts.append(f"Current phone: {identifiers['current_phone']}")
        parts.append(f"Email hash:    {identifiers['email_hash']}")
        if identifiers["historical"]:
            parts.append("Historical changes:")
            for h in identifiers["historical"]:
                parts.append(f"  {h['event_time']} field={h['field']} old={h['old_value']} new={h['new_value']}")
    else:
        parts.append("=== USER IDENTITY: NOT FOUND in user_identities.csv ===")
        parts.append("(no matching current or historical email)")
    parts.append("")

    if activities:
        parts.append(f"=== RELEVANT SYSTEM ACTIVITIES (showing up to 15 of {len(activities)}) ===")
        # Prioritise deletion-related events
        del_acts = [a for a in activities if "DELET" in a.get("event_type","").upper() or "BACKUP" in a.get("event_type","").upper() or "SYNC" in a.get("event_type","").upper() or "RESTORE" in a.get("event_type","").upper()]
        other_acts = [a for a in activities if a not in del_acts]
        show_acts = (del_acts + other_acts)[:15]
        for act in show_acts:
            parts.append(
                f"  [{act['activity_id']}] {act['event_time']} "
                f"{act['event_type']} resource={act['resource_id']} result={act['reported_result']}"
            )
    else:
        parts.append("=== RELEVANT SYSTEM ACTIVITIES: none found ===")
    parts.append("")

    if evidence_snippets:
        parts.append(f"=== EVIDENCE FILES (top {min(3,len(evidence_snippets))}) ===")
        for fid, snippet in evidence_snippets[:3]:  # max 3 files
            meta = evidence_by_id.get(fid, {})
            parts.append(f"--- {fid} captured={meta.get('captured_at','')} ---")
            parts.append(snippet[:1200])  # 1200 chars max per file
            parts.append("")
    else:
        parts.append("=== EVIDENCE FILES: none relevant found ===")

    parts.append("")
    parts.append("Based ONLY on the evidence above (not on reported_status claims), "
                 "determine the true deletion state at audit_at and produce the required output JSON.")

    return "\n".join(parts)


def format_rules_for_prompt() -> str:
    lines = []
    for r in deletion_rules:
        lines.append(f"  {r['rule_id']}: {r['data_category']} [{r['condition']}] -> {r['required_action']}")
    return "\n".join(lines)


RULES_TEXT = format_rules_for_prompt()

# ---------------------------------------------------------------------------
# Output validation & sorting
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
    """Sort steps by phase->operation->system_id->resource_id then renumber."""
    def sort_key(s):
        phase = PHASE_ORDER.get(s.get("phase", ""), 99)
        op    = OPERATION_ORDER.get(s.get("operation", ""), 99)
        sys_  = s.get("system_id", "")
        res   = s.get("resource_id", "")
        return (phase, op, sys_, res)

    steps_sorted = sorted(steps, key=sort_key)
    for i, s in enumerate(steps_sorted, start=1):
        s["step_no"] = i
    return steps_sorted


def parse_llm_response(text: str) -> dict | None:
    """Extract and parse JSON from LLM response."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return None


def validate_and_fix(parsed: dict, case_id: str) -> tuple[str, list[dict]]:
    """Return (deletion_status, steps) after basic validation."""
    status = parsed.get("deletion_status", "NOT_APPLICABLE").strip().upper()
    if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
        status = "NOT_APPLICABLE"

    steps = parsed.get("steps", [])
    if not isinstance(steps, list):
        steps = []

    if status == "NOT_APPLICABLE":
        return status, []

    valid_steps = []
    for s in steps:
        if not isinstance(s, dict):
            continue
        cleaned = {
            "step_no":     s.get("step_no", 0),
            "phase":       s.get("phase", ""),
            "system_id":   s.get("system_id", ""),
            "resource_id": s.get("resource_id", ""),
            "operation":   s.get("operation", ""),
            "state":       s.get("state", ""),
            "evidence_id": s.get("evidence_id", ""),
        }
        valid_steps.append(cleaned)

    valid_steps = sort_and_renumber(valid_steps)
    return status, valid_steps

# ---------------------------------------------------------------------------
# Main processing loop
# ---------------------------------------------------------------------------

def process_case(case: dict) -> dict:
    """Process one deletion request and return {case_id, deletion_status, steps_json}."""
    case_id  = case["case_id"]
    email    = case["email"].strip()
    audit_at = case["audit_at"].strip()
    req_text = case["request_text"].strip()

    # Resolve identity
    user = resolve_user(email)
    identifiers = get_all_identifiers(user) if user else None

    # Collect activities and evidence
    if identifiers:
        activities = get_activities_for_user(identifiers["user_id"], identifiers, audit_at)
        evidence_snippets = find_relevant_evidence(identifiers, audit_at)
    else:
        activities = []
        evidence_snippets = []

    # Build prompts
    sys_prompt  = SYSTEM_PROMPT_AUDIT.format(rules=RULES_TEXT)
    user_prompt = build_user_prompt(case, identifiers, activities, evidence_snippets)

    # Call LLM
    try:
        raw = call_llm(sys_prompt, user_prompt, max_tokens=1200)
    except Exception as exc:
        print(f"    LLM error on {case_id}: {exc}", file=sys.stderr)
        return {
            "case_id": case_id,
            "deletion_status": "NOT_APPLICABLE",
            "steps_json": "[]",
        }

    # Parse response
    parsed = parse_llm_response(raw)
    if parsed is None:
        print(f"    WARNING: Could not parse JSON for {case_id}. Raw: {raw[:200]}", file=sys.stderr)
        return {
            "case_id": case_id,
            "deletion_status": "NOT_APPLICABLE",
            "steps_json": "[]",
        }

    # Validate & sort
    status, steps = validate_and_fix(parsed, case_id)

    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps_json": json.dumps(steps, separators=(",", ":")),
    }


def main():
    print(f"\n{'='*60}")
    print("Ghost Data Still Exists -- Deletion Audit Agent")
    print(f"Model: {MODEL}")
    print(f"Cases: {len(deletion_requests)}")
    print(f"Output: {OUTPUT_CSV}")
    print(f"{'='*60}\n")

    results = []
    total = len(deletion_requests)

    for i, case in enumerate(deletion_requests, start=1):
        case_id = case["case_id"]
        print(f"[{i:3d}/{total}] Processing {case_id}...", end=" ", flush=True)
        result = process_case(case)
        results.append(result)
        print(f"{result['deletion_status']}")

    # Sort by case_id
    results.sort(key=lambda r: r["case_id"])

    # Write output.csv
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    print(f"\nDone. Written {len(results)} rows to {OUTPUT_CSV}")

    # Sanity check
    from collections import Counter
    counts = Counter(r["deletion_status"] for r in results)
    print(f"Status distribution: {dict(counts)}")


if __name__ == "__main__":
    main()
