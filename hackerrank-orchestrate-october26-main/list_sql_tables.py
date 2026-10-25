import sqlite3, csv
from pathlib import Path

DATASET = Path('dataset')
with open(DATASET / 'evidence_files.csv', encoding='utf-8') as f:
    ev_files = [r for r in csv.DictReader(f) if r['file_path'].endswith('.sql')]

all_tables = set()
for ef in ev_files:
    p = DATASET / ef['file_path']
    txt = p.read_text(encoding='utf-8')
    conn = sqlite3.connect(':memory:')
    conn.executescript(txt)
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]
    all_tables.update(tables)

print(f"Found {len(all_tables)} distinct tables:")
for t in sorted(all_tables):
    print(" ", t)
