"""
Comprehensive Evidence Parser & Matcher
Tests parsing and resource extraction across all 94 evidence files.
"""

import csv
import json
import re
from pathlib import Path

DATASET = Path("dataset")

with open(DATASET / "evidence_files.csv", encoding="utf-8") as f:
    ev_files = list(csv.DictReader(f))

print(f"Total evidence files to index: {len(ev_files)}")

# 1. Parse JSON files
json_records = []
for ef in ev_files:
    if ef["file_path"].endswith(".json"):
        p = DATASET / ef["file_path"]
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                json_records.append((ef["file_id"], ef["origin"], ef["captured_at"], data))
            except Exception as e:
                print(f"Error loading {ef['file_id']}: {e}")

print(f"Loaded {len(json_records)} JSON evidence files.")

# 2. Parse SQL files
sql_records = []
for ef in ev_files:
    if ef["file_path"].endswith(".sql"):
        p = DATASET / ef["file_path"]
        if p.exists():
            txt = p.read_text(encoding="utf-8")
            sql_records.append((ef["file_id"], ef["origin"], ef["captured_at"], txt))

print(f"Loaded {len(sql_records)} SQL evidence files.")

# 3. Parse Log files
log_records = []
for ef in ev_files:
    if ef["file_path"].endswith(".log") or ef["file_path"].endswith(".txt"):
        p = DATASET / ef["file_path"]
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            log_records.append((ef["file_id"], ef["origin"], ef["captured_at"], txt))

print(f"Loaded {len(log_records)} Log/Text evidence files.")
