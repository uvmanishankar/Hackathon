# Ghost Data Still Exists — Solution README

## Overview

AI-powered deletion audit agent for the HackerRank Orchestrate October 2026 challenge.
The agent audits whether a user's personal data has been fully deleted across all platform systems and produces an ordered remediation plan if it has not.

## Architecture

```
code/
├── main.py                    # Main agent entry point
└── evaluation/
    ├── evaluation_report.md   # Accuracy analysis and custom test cases
    └── usage_report.md        # Token usage and cost analysis
```

**Pipeline per case:**
1. **Identity resolution** — looks up request email in current + historical identity tables
2. **Activity filtering** — finds relevant system_activity rows (up to audit_at cutoff)
3. **Evidence extraction** — reads relevant evidence files (logs, JSON, SQL, images)
4. **LLM reasoning** — sends context to Groq llama-3.3-70b-versatile for deletion status + steps
5. **Deterministic post-processing** — sorts steps per spec, renumbers, validates JSON

## Setup

### Requirements

- Python 3.10+
- Groq API key (set `GROQ_API_KEY` environment variable)

### Install dependencies

```bash
pip install groq pandas python-dotenv
```

Optional (for PDF evidence files):
```bash
pip install pdfplumber
```

### Set your API key

Either export in your shell:
```bash
export GROQ_API_KEY=your_key_here       # macOS / Linux
set GROQ_API_KEY=your_key_here          # Windows CMD
$env:GROQ_API_KEY="your_key_here"       # Windows PowerShell
```

Or create a `.env` file in the repository root:
```
GROQ_API_KEY=your_key_here
```

## Running

From the **repository root**:

```bash
python code/main.py
```

Output is written to `output.csv` in the repository root.

## Model

- **Provider**: Groq
- **Model**: `llama-3.3-70b-versatile`
- **Temperature**: 0 (deterministic)

## Output Format

```csv
case_id,deletion_status,steps_json
case_33,COMPLETE,"[{""step_no"":1,""phase"":""VERIFICATION"",...}]"
case_34,INCOMPLETE,"[{""step_no"":1,""phase"":""FINDING"",...}]"
```

`deletion_status` is one of: `COMPLETE`, `INCOMPLETE`, `NOT_APPLICABLE`

`steps_json` is an ordered JSON array of step objects per the problem specification.

## Submission Checklist

- [x] `output.csv` at repository root with 518 rows sorted by `case_id`
- [x] Valid JSON array in every `steps_json` field
- [x] Consecutive step numbers starting at 1
- [x] Steps ordered: FINDING → REMEDIATION → VERIFICATION
- [x] FINDING steps cite `evidence_id` from participant-visible files
- [x] REMEDIATION and future VERIFICATION steps use `evidence_id=""`
- [x] `code/evaluation/evaluation_report.md` included
- [x] `code/evaluation/usage_report.md` included
- [x] No API keys in code or config
- [x] No `dataset/` in `code.zip`

## Packaging (Windows PowerShell)

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

## Challenge Submission URL

https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists
