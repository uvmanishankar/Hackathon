import os, json

records_dir = 'dataset/evidence'
for root, dirs, files in os.walk(records_dir):
    for f in files:
        if f.endswith('.json'):
            p = os.path.join(root, f)
            try:
                data = json.loads(open(p, encoding='utf-8').read())
                keys = list(data.keys())
                coll = data.get("collection") or data.get("table") or data.get("type") or ""
                num_recs = len(data.get("records") or data.get("items") or data.get("rows") or [])
                print(f"{f:45s} | keys={keys[:4]} | coll={coll} | recs={num_recs}")
            except Exception as e:
                print(f"Error reading {f}: {e}")
