# Ghost Data Still Exists - Solution

## Overview

This solution audits each deletion request against identity history, system
activity, and participant-provided evidence. Deterministic Python code performs
identity resolution, evidence parsing, record-state evaluation, policy
application, and ordered output generation. Groq is optional and is used only
to classify request text that the deterministic intent rules do not recognize.

## Requirements

- Python 3.10 or newer
- No required third-party packages
- Optional: `groq` and a `GROQ_API_KEY` environment variable for ambiguous
  request-intent classification
- Optional: `pdfplumber` for PDF evidence when the `pdftotext` utility is not
  available
- Optional: `pytesseract`, Pillow, and the local Tesseract OCR executable for
  PNG/JPEG/WebP screenshot evidence

Install optional packages only if needed:

```powershell
python -m pip install groq pdfplumber pytesseract pillow
```

Install the Tesseract executable separately. On Windows, set its path when it
is not on `PATH` or in the standard installation directory:

```powershell
$env:TESSERACT_CMD = "C:\Program Files\Tesseract-OCR\tesseract.exe"
```

Screenshot OCR runs locally; image contents are not sent to an external
service. The parser keeps the evidence file ID, manifest path, capture time,
source image name, OCR text, and confidence with each extracted observation.
It only attaches a user ID or email recognized in the same visual row as a
resource. OCR-only resources without a direct owner are not linked through
file co-occurrence.

Set the optional Groq key in PowerShell:

```powershell
$env:GROQ_API_KEY = "your_key_here"
```

The program does not load `.env` files. Do not put credentials in source code
or the submission archive.

## Account linking

Direct identifier evidence is preferred. Activity-based account associations
are made only when the status/time candidate group is one-to-one and the
resource has no explicit conflicting owner evidence. An account directly
matched to exactly one user may also be included when its deletion-worker
event falls within that request's window; its state is still determined from
observations at or before `audit_at`. Ambiguous activity-only groups are left
unlinked rather than assigned by ordering.

## Run

From the repository root, generate predictions for all 518 requests:

```powershell
python code\main.py
```

The generated `output.csv` is written to the repository root. Run the sample
evaluation against `dataset/sample_output.csv` with:

```powershell
python code\main.py --eval
```

To also generate a per-case mismatch report and position-aligned field
accuracy metrics:

```powershell
python code\main.py --eval --mismatch-report
```

The report is written to
`code/evaluation/sample_mismatch_report.md`. It lists missing/extra semantic
steps, evidence-ID mismatches, and expected/predicted step arrays.

Optional linking diagnostics can be enabled for local troubleshooting:

```powershell
python code\main.py --eval --debug-linking
```

Diagnostics may print user identifiers and should not be used in shared logs.

## Output

`output.csv` has the required columns:

```csv
case_id,deletion_status,steps_json
```

Each request receives one `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`
prediction. Steps are JSON arrays ordered by phase, operation, system, and
resource as specified in the challenge.

## Submission contents

The `code.zip` archive contains this README, the repository README, the
standalone `code/main.py` entry point, and the evaluation reports. The dataset,
credentials, caches, and exploratory scripts are excluded.

Create the archive from the repository root in PowerShell:

```powershell
@'
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

files = [
    "README.md",
    "code/README.md",
    "code/main.py",
    "code/evaluation/evaluation_report.md",
    "code/evaluation/usage_report.md",
    "code/evaluation/sample_mismatch_report.md",
]
with ZipFile("code.zip", "w", compression=ZIP_DEFLATED) as archive:
    for name in files:
        path = Path(name)
        if path.exists():
            archive.write(path, name)
'@ | python -
```

Submit `output.csv` and `log.txt` separately in their corresponding HackerRank
submission fields.

Challenge: <https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists>
