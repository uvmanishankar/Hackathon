import json, re
from pathlib import Path

user_to_resources = {}

# Check JSON files
for p in Path('dataset/evidence').rglob('*.json'):
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
        def walk(obj):
            if isinstance(obj, dict):
                uid = obj.get('user_id') or obj.get('customer_reference') or obj.get('subject_reference')
                rid = obj.get('resource_id') or obj.get('account_id')
                if uid and rid and 'user_' in str(uid):
                    user_to_resources.setdefault(str(uid), set()).add(str(rid))
                for v in obj.values():
                    walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
        walk(data)
    except Exception:
        pass

# Check SQL files
for p in Path('dataset/evidence').rglob('*.sql'):
    try:
        txt = p.read_text(encoding='utf-8')
        for m in re.finditer(r"VALUES\s*\(\s*'([^']+)'\s*,\s*'([^']+)'", txt):
            r1, r2 = m.group(1), m.group(2)
            if 'user_' in r1:
                user_to_resources.setdefault(r1, set()).add(r2)
            elif 'user_' in r2:
                user_to_resources.setdefault(r2, set()).add(r1)
    except Exception:
        pass

print(f"Found mappings for {len(user_to_resources)} users!")
for u in sorted(user_to_resources.keys())[:15]:
    print(f"  {u}: {user_to_resources[u]}")
