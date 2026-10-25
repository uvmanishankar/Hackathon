import os

terms = ['account_001', 'account_007', 'support_001', 'export_001']
for root, dirs, files in os.walk('dataset'):
    for f in files:
        p = os.path.join(root, f)
        try:
            with open(p, 'r', encoding='utf-8', errors='ignore') as fp:
                c = fp.read()
                for t in terms:
                    if t in c:
                        print(f"Found {t} in {p}")
        except Exception:
            pass
