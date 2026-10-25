# Usage Report — Ghost Data Still Exists

## Final Full-Dataset Run Summary

This report covers the final run that produced `output.csv` for the 518-case dataset.

---

## Model Configuration

| Field | Value |
|-------|-------|
| Provider | Groq |
| Model name | `llama-3.3-70b-versatile` |
| Temperature | 0 (deterministic) |
| Max tokens (output) | 4096 per call |
| API endpoint | `https://api.groq.com/openai/v1/chat/completions` |

---

## Token Usage Estimates

Token counts are estimated based on prompt structure. Actual counts depend on evidence file sizes per case.

### Per-Request Breakdown (Estimates)

| Component | Avg Tokens (Input) |
|-----------|-------------------|
| System prompt | ~800 |
| Case metadata | ~150 |
| Identity block | ~100 |
| Activities (up to 60 rows) | ~1,200 |
| Evidence snippets (up to 8 files × 4000 chars) | ~8,000 |
| **Total input per call** | **~10,250** |

| Component | Avg Tokens (Output) |
|-----------|---------------------|
| JSON response (steps array) | ~800 |
| **Total output per call** | **~800** |

### Full Dataset

| Metric | Estimate |
|--------|----------|
| Total cases | 518 |
| Model calls | 518 (1 per case) |
| Avg input tokens/call | ~10,250 |
| Avg output tokens/call | ~800 |
| Total input tokens | ~5,309,500 |
| Total output tokens | ~414,400 |
| **Total tokens** | **~5,723,900** |

---

## Cost Estimates

Groq pricing for `llama-3.3-70b-versatile` (as of October 2026):

| Tier | Rate |
|------|------|
| Input tokens | $0.59 / 1M tokens |
| Output tokens | $0.79 / 1M tokens |

| Metric | Estimate |
|--------|----------|
| Input cost | ~$3.13 (5.31M × $0.59/1M) |
| Output cost | ~$0.33 (0.41M × $0.79/1M) |
| **Total estimated cost** | **~$3.46** |
| **Per-request cost** | **~$0.0067** |

---

## Per-Model Totals

Only one model was used in this run.

| Model | Provider | Calls | Input Tokens | Output Tokens | Est. Cost |
|-------|----------|-------|-------------|--------------|-----------|
| llama-3.3-70b-versatile | Groq | 518 | ~5,309,500 | ~414,400 | ~$3.46 |
| **Overall** | | **518** | **~5,309,500** | **~414,400** | **~$3.46** |

---

## Runtime

| Metric | Value |
|--------|-------|
| Average latency per call | ~3–8 seconds (Groq is very fast) |
| Estimated total runtime | ~30–70 minutes for 518 cases |
| Parallelism | Sequential (1 call at a time) |

To speed up future runs, cases can be processed in parallel batches (Groq supports high throughput).

---

## Notes

- Token counts are estimates because evidence file sizes vary significantly per case. Cases with large SQL snapshots or multi-file evidence logs will have higher input token counts.
- Evidence is truncated at 80,000 characters per file and snippets are capped at 4,000 characters per file, limiting maximum input token spike.
- No caching was used in the final run. A future optimization could cache evidence file content (already done in-memory) and reuse identity resolution across cases for the same user.
- The Groq free tier rate limits apply; for production use, ensure the API key has sufficient quota.
