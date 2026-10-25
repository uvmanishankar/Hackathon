import csv

with open('dataset/deletion_requests.csv', encoding='utf-8') as f:
    requests = list(csv.DictReader(f))

candidates = []
for r in requests:
    t = r['request_text'].lower()
    if (
        'not asking for deletion' in t
        or 'leave the account' in t
        or 'leave my profile' in t
        or 'do not close' in t
        or "don't delete" in t
        or 'not a request to erase' in t
        or 'continue using' in t
        or 'without removing' in t
        or "keep the account" in t
    ):
        candidates.append((r['case_id'], r['request_text']))

print(f"Total non-deletion cases found: {len(candidates)}")
for c, txt in candidates:
    print(c, "-->", txt[:80])
