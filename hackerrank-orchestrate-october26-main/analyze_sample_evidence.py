import csv, json

with open('dataset/sample_output.csv', encoding='utf-8') as f:
    sample_out = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(f)}

with open('dataset/sample_deletion_requests.csv', encoding='utf-8') as f:
    sample_reqs = list(csv.DictReader(f))

with open('dataset/evidence_files.csv', encoding='utf-8') as f:
    ev_meta = {r['file_id']: r for r in csv.DictReader(f)}

for r in sample_reqs:
    cid = r['case_id']
    status, steps = sample_out[cid]
    ev_ids = sorted(list({s['evidence_id'] for s in steps if s['evidence_id']}))
    audit_at = r['audit_at']
    parts = []
    for eid in ev_ids:
        cap = ev_meta.get(eid, {}).get('captured_at', '')
        orig = ev_meta.get(eid, {}).get('origin', '')
        parts.append(f"{eid} ({orig} @ {cap})")
    print(f"{cid:8s} {status:11s} audit={audit_at} -> ev: {', '.join(parts)}")
