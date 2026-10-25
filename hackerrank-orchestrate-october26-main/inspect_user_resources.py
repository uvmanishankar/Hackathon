import csv, json

with open('dataset/sample_deletion_requests.csv', encoding='utf-8') as f:
    sample_reqs = list(csv.DictReader(f))

with open('dataset/sample_output.csv', encoding='utf-8') as f:
    sample_out = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(f)}

with open('dataset/user_identities.csv', encoding='utf-8') as f:
    identities = {r['email'].lower(): r for r in csv.DictReader(f)}
    id_by_uid = {r['user_id']: r for r in identities.values()}

with open('dataset/user_audit_log.csv', encoding='utf-8') as f:
    for a in csv.DictReader(f):
        if a.get('field_name') == 'email' and a.get('old_value'):
            identities[a['old_value'].lower()] = id_by_uid.get(a['user_id'])

for r in sample_reqs:
    cid = r['case_id']
    email = r['email'].strip().lower()
    user = identities.get(email)
    uid = user['user_id'] if user else 'NONE'
    status, steps = sample_out[cid]
    rids = [f"{s['system_id']}:{s['resource_id']}" for s in steps]
    print(f"{cid:8s} {uid:10s} rep={r['reported_at']} -> {rids}")
