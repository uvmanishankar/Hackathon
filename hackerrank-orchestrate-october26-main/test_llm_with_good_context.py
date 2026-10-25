"""
Test calling LLM with the actual evidence and activities
"""

import os
import sys
sys.path.insert(0, 'code')
import json
from audit_engine import resolve_user, get_all_identifiers
from main import call_llm, SYSTEM_PROMPT_AUDIT, RULES_TEXT

# For case_01:
case_01 = {
    "case_id": "case_01",
    "email": "amina.elmasri@gmail.com",
    "requested_at": "2026-08-18T09:14:00Z",
    "reported_status": "COMPLETE",
    "reported_at": "2026-08-20T16:42:00Z",
    "audit_at": "2026-09-03T11:30:00Z",
    "request_text": "Hi, I haven't used this account in years and would like it closed. Please remove the profile and the personal details attached to it."
}

user = resolve_user(case_01["email"])
idents = get_all_identifiers(user)

ev54_text = open("dataset/evidence/databases/customer_accounts_failover_replica_20260902.sql", encoding="utf-8").read()

activity_text = """[activity_3342] 2026-08-20T16:41:43Z DELETE_RECORD account_001 res=SUCCESS Deletion worker reported the requested operation as completed. Target resource: account_001."""

user_prompt = f"""=== CASE case_01 ===
Email: {case_01['email']}
Requested at: {case_01['requested_at']}
Reported status: {case_01['reported_status']}
Reported at: {case_01['reported_at']}
Audit cutoff (audit_at): {case_01['audit_at']}
Request text: {case_01['request_text']}

=== USER IDENTITY ===
user_id: {idents['user_id']}
Current name: {user.get('name')}
Current email: {user.get('email')}
Current phone: {user.get('phone')}
Email hash: {user.get('email_hash')}

=== RELEVANT SYSTEM ACTIVITIES ===
{activity_text}

=== EVIDENCE FILES ===
--- evidence_54 captured=2026-09-02T23:00:00Z ---
{ev54_text}

Based ONLY on the evidence above, determine the true deletion state at audit_at and produce the required output JSON.
Notice: account_001 was deleted by deletion_worker before reported_at, and in evidence_54 (failover_replica snapshot), account_001 is completely ABSENT.
"""

sys_prompt = SYSTEM_PROMPT_AUDIT.format(rules=RULES_TEXT)
print("Calling LLM for case_01...")
resp = call_llm(sys_prompt, user_prompt)
print("LLM RESPONSE FOR CASE 01:\n", resp)
