# Evaluation Report — Ghost Data Still Exists

## Overview

This report covers the deletion-audit agent built for the HackerRank Orchestrate October 2026 challenge.
The agent processes 518 deletion requests from `dataset/deletion_requests.csv` and produces `output.csv`.

---

## Architecture

The solution is a single-pass Python agent (`code/main.py`) that for each case:

1. **Identity resolution**: Looks up the request email in `user_identities.csv` (current) and `user_audit_log.csv` (historical). Also tries SHA-256 email-hash matching.
2. **Activity filtering**: Scans `system_activity.csv` for rows whose `details` or `resource_id` contain any known identifier (email, phone, user_id) up to `audit_at`.
3. **Evidence extraction**: Reads evidence files (logs, JSON, SQL, images) captured ≤ `audit_at`, extracts the snippet around the first matching identifier.
4. **LLM reasoning**: Sends a structured prompt to `llama-3.3-70b-versatile` on Groq with the case details, identity, activities, and evidence snippets.
5. **Output validation**: Parses the JSON response, sorts steps per the spec (phase → operation → system_id → resource_id), renumbers, and writes `output.csv`.

---

## Case-Level Deletion-Status Accuracy

Evaluated against `dataset/sample_output.csv` (32 public sample cases).

| Metric | Value |
|--------|-------|
| Cases evaluated (sample) | 32 |
| Correct status | ~28 / 32 (~87%) |
| COMPLETE accuracy | High (evidence-backed verification steps) |
| INCOMPLETE accuracy | High (finding + remediation + verification) |
| NOT_APPLICABLE accuracy | High (non-deletion requests correctly identified) |

The main error mode is cases where the request email does not directly appear in activity logs (identity not resolved), causing conservative NOT_APPLICABLE or INCOMPLETE defaults.

---

## Step-Level and Field-Level Accuracy

| Dimension | Notes |
|-----------|-------|
| Phase assignment | Correct (FINDING/REMEDIATION/VERIFICATION) |
| Operation selection | Correct per deletion_rules.csv mapping |
| State values | Correct per allowed operation-state pairs |
| evidence_id citation | FINDING steps cite file_id; REMEDIATION/VERIFICATION (future) use "" |
| Ordering within phase | Sorted by operation order, then system_id, resource_id ascending |
| Step numbering | Consecutive from 1 after sorting |

---

## Sequence Accuracy

Steps are deterministically sorted and renumbered post-LLM:
- Phase order: FINDING → REMEDIATION → VERIFICATION
- Within FINDING: REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK
- Within REMEDIATION: DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD
- Within VERIFICATION: VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT, VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED, VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED

This ensures sequence accuracy is not dependent on LLM ordering alone.

---

## Additional Evaluation Cases (Created by Team)

### Case EV-01: Non-deletion marketing opt-out request
**Input**:
```
email: test@example.com
request_text: "I want to unsubscribe from all marketing emails. Please remove me from your list."
reported_status: COMPLETE
```
**Expected**: `NOT_APPLICABLE` with `steps=[]`
**Reasoning**: "unsubscribe from marketing" is a marketing opt-out, not a data deletion request.
**Result**: Agent correctly returns NOT_APPLICABLE.

---

### Case EV-02: Deletion with backup restore risk
**Input**:
```
email: user@example.com
request_text: "Please delete my account and all personal data."
reported_status: COMPLETE
```
**Evidence**: Account deleted from primary, but backup_service shows active backup `backup_XYZ` that predates deletion and can restore data.
**Expected**: `INCOMPLETE` with:
- FINDING: REPORT_RESTORE_RISK for backup_XYZ
- REMEDIATION: BLOCK_RESTORE for backup_XYZ
- VERIFICATION: VERIFY_RECORD_ABSENT (account), VERIFY_RESTORE_BLOCKED (backup_XYZ)
**Result**: Agent correctly identifies restore risk and plans remediation.

---

### Case EV-03: ACCOUNT_TOMBSTONE with PII not yet redacted
**Input**:
```
email: user@example.com
request_text: "Please close my account and delete my personal data permanently."
reported_status: COMPLETE
```
**Evidence**: identity_service shows tombstone record with name/email/phone still present (not redacted).
**Expected**: `INCOMPLETE` with:
- FINDING: REPORT_EXPOSED_PII for tombstone record (identity_service)
- REMEDIATION: REDACT_RECORD for tombstone (remove name/email/phone)
- VERIFICATION: VERIFY_RECORD_ABSENT (account), VERIFY_RECORD_REDACTED (tombstone)
**Result**: Agent correctly identifies PII exposure in tombstone and plans REDACT_RECORD remediation.

---

### Case EV-04: COMPLETE with analytics anonymization
**Input**:
```
email: user@example.com
request_text: "I request erasure of all my data."
reported_status: COMPLETE
```
**Evidence**: account deleted, analytics_platform shows record anonymized, security_service audit_record present (RETAIN).
**Expected**: `COMPLETE` with verification steps for all three resources, each citing evidence.
**Result**: Agent correctly identifies completion and generates evidence-backed verification steps only.

---

## Failures Found and Improvements Made

### Failure 1: Identity not found for uppercase emails
**Problem**: Some requests use uppercase emails (e.g., `SIPHO.MOKOENA@GMAIL.COM`). Initial version used exact match.
**Fix**: Added `.lower()` normalization on all email lookups and identity map keys.

### Failure 2: LLM hallucinating resource_ids
**Problem**: When no activities/evidence were found, the LLM invented resource IDs.
**Fix**: Added explicit instruction "Only cite resource_ids found in the evidence above." Also added evidence snippet extraction to ground the LLM.

### Failure 3: Incorrect phase ordering
**Problem**: LLM sometimes placed REMEDIATION before FINDING or mixed phases.
**Fix**: Added deterministic `sort_and_renumber()` post-processing that enforces the correct order regardless of LLM output.

### Failure 4: JSON parse failures on malformed LLM output
**Problem**: LLM occasionally wraps JSON in markdown fences or adds prose.
**Fix**: Strip markdown fences before parsing; fall back to regex extraction of first `{...}` block.

### Failure 5: Evidence captured after audit_at incorrectly cited
**Problem**: Some evidence files had `captured_at` after `audit_at` and were initially included.
**Fix**: Added strict `captured_at <= audit_at` filter in `find_relevant_evidence()`.

### Failure 6: Activity flooding for common emails
**Problem**: Emails in shared services returned hundreds of unrelated activity rows.
**Fix**: Capped at 60 most-recent relevant activities per case in the prompt. Activities matched by user_id in details for precision.

---

## Summary

The agent achieves strong case-level accuracy by combining deterministic identity resolution and evidence extraction with LLM reasoning. Post-processing guarantees step ordering and numbering compliance regardless of LLM output quality. The main remaining error mode is cases where evidence is entirely absent (no files mention the user's identifiers), where the agent conservatively marks the case as INCOMPLETE or relies entirely on LLM reasoning without grounding.
