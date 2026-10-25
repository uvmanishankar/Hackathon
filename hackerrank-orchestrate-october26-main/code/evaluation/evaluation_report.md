# Evaluation Report - Ghost Data Still Exists

## Automated sample evaluation

The deterministic evaluator in `code/main.py --eval` compares all 32 supplied
sample requests with `dataset/sample_output.csv`.

| Metric | Result |
| --- | ---: |
| Deletion-status accuracy | 32/32 (100%) |
| Exact output-row accuracy (status and full step objects) | 18/32 (56.2%) |
| Step precision | 1.00 |
| Step recall | 0.91 |
| Step F1 | 0.95 |
| Exact semantic step sequences (phase/system/resource/operation/state) | 18/32 |
| Exact full step arrays including evidence IDs | 18/32 |
| Evidence ID accuracy on matched steps | 176/176 |
| Account IDs matching sample expectations | 24 |
| Account IDs extra versus sample expectations | 0 |
| Expected account IDs not predicted | 8 |

The step-field precision/recall values are micro-averaged over semantic step
tuples: 176 true positives, no extra predicted tuples, and 17 expected tuples
not predicted. All 176 matched semantic steps cite the expected evidence ID.
The exact-row metric compares deletion status and every step field, including
step number and evidence ID.
Running `python code\main.py --eval` prints each metric above directly from the
current implementation and `dataset/sample_output.csv`; the table is not a
manually entered result.

Run `python code\main.py --eval --mismatch-report` to generate
`code/evaluation/sample_mismatch_report.md`, including per-case missing and
extra steps, evidence-ID mismatches, and expected/predicted arrays. It also
reports position-aligned field accuracy (each compared position is scored
against the corresponding expected step; missing positions count as incorrect):

| Field | Correct / compared | Accuracy |
| --- | ---: | ---: |
| `step_no` | 176/193 | 91.2% |
| `phase` | 176/193 | 91.2% |
| `system_id` | 145/193 | 75.1% |
| `resource_id` | 145/193 | 75.1% |
| `operation` | 150/193 | 77.7% |
| `state` | 150/193 | 77.7% |
| `evidence_id` | 176/193 | 91.2% |

These position-aligned scores are diagnostic and should not be confused with
the semantic tuple or matched-step evidence metrics above.

Account figures are a sample-output comparison, not independent proof that an
association is correct. The account matcher abstains when its status/time
candidate group is ambiguous; a one-case/one-resource group remains a
provisional heuristic association. Do not interpret expected-output agreement
as identity evidence.

All 14 non-exact semantic step sequences differ in their step sets; none are
ordering-only mismatches. The emitted arrays are still sorted by the required
phase, operation, `system_id`, and `resource_id` ordering. The exact-sequence
score therefore reflects missed or extra steps as well as sequence equality.

`--eval -v` prints per-case step differences and account IDs that differ from
the sample answer. `--debug-linking` enables detailed local traces, including
resolved identifiers; those diagnostics should not be shared publicly.

## Additional evaluation cases

The following supplemental scenarios were created to exercise policy behavior.
They are scenario specifications and are not included in the automated 32-case
metrics above.

### Case EV-01: Marketing opt-out, not a deletion request

**Input:** A user asks to unsubscribe from marketing emails and be removed from
the marketing list.

**Expected:** `NOT_APPLICABLE` with `steps_json` equal to `[]`. A marketing
preference change alone does not authorize a personal-data deletion audit.

### Case EV-02: Backup can restore deleted data

**Input:** The primary account is absent, but a backup predating the deletion
can restore the user's data.

**Expected:** `INCOMPLETE`, with a restore-risk finding, a `BLOCK_RESTORE`
remediation step, and verification for the account and blocked restore path.

### Case EV-03: Tombstone still contains direct identifiers

**Input:** A retained account tombstone contains the user's name, email, or
phone number.

**Expected:** `INCOMPLETE`, with an exposed-PII finding, a `REDACT_RECORD`
remediation step, and a redaction verification. The tombstone's stable internal
user reference may remain when policy permits it.

### Case EV-04: Properly anonymized analytics and retained audit record

**Input:** The account is absent, analytics data is irreversibly anonymized,
and a security audit record required by policy remains.

**Expected:** `COMPLETE`, with evidence-backed verification for the account,
anonymized analytics record, and retained audit record.

## Mismatch investigation and improvements

- **Evidence fallback selected an unrelated snapshot:** For an account known
  absent only from deletion activity, the fallback always preferred the
  newest SQL file, even when it was from an unrelated system and the user had
  a newer directly linked evidence bundle. It now prefers the latest
  pre-audit file already matched to that user's identity, with a snapshot
  fallback only when no such file exists. This corrected the `case_31`
  citation from `evidence_57` to `evidence_51` without changing the linked
  resource set.

- **Ambiguous account association:** The earlier account linker paired
  status/time-compatible resources and cases by sorted order. Matching status
  and time establishes eligibility, not identity. It was replaced with
  conservative one-case/one-resource linking; ambiguous groups are left
  unresolved. A resource is also excluded from activity linking when its
  evidence explicitly resolves to a different user's identity.
- **Out-of-window account activity:** A directly identified account is linked
  to a deletion request only when its deletion-worker event falls within that
  request's time window. This removed the extra `account_6523` prediction for
  `case_17`; the observation's deletion event occurred after the request's
  reported time.
- **Unattributed anonymized analytics:** File co-occurrence and a deletion
  event are not sufficient to assign an analytics record whose evidence
  explicitly says it has no direct identifier. Excluding that heuristic
  association removed the extra `analytics_9447` prediction for `case_11`.
  Other anonymous records remain unresolved unless stronger evidence exists.
- **Direct identity account recovery:** A uniquely identity-claimed account
  with a deletion-worker event inside the request window can be linked even
  when the identifying observation was captured after `audit_at`. Its state is
  still computed only from audit-eligible observations. This recovers
  `account_3866` for `case_27`; the matching pre-audit service export reports
  the account absent.
- **Expected-output account mismatches remain:** The sample comparison reports
  eight expected account IDs not predicted and no extra IDs. Several missing
  accounts are in candidate groups shared by multiple requests; the available
  status/time evidence does not identify which user owns which resource.
  These cases remain unresolved rather than being "fixed" by positional
  pairing.
- **Remaining exact-row mismatches are evidence-limited:** The current mismatch
  report has 14 non-exact rows: 12 contain missing account or analytics steps
  whose resource records have no direct owner or are eligible for multiple
  requests; two retained audit IDs are absent from parsed evidence and
  `system_activity.csv`. Incomplete or conflicting ownership evidence remains
  unresolved rather than inferred from timestamps, ordering, or shared-file
  co-occurrence.
- **Missing retained audit verifications:** `audit_record_6645` and
  `audit_record_5569` do not appear in parsed evidence observations or
  `system_activity.csv`; there is no source-backed resource to verify for
  `case_18` or `case_20`.
- **Diagnostics obscured normal output:** Linking and trace diagnostics are
  gated behind `--debug-linking`, leaving the regular evaluator output concise.
- **Sequence score needs step-coverage work:** Since all non-exact sample arrays
  also differ in their step sets, the next improvement is evidence discovery
  and resource coverage, not changing the deterministic sort order.
- **Screenshot OCR is conservative, not complete:** The local OCR path now
  processes all 11 supplied PNGs and extracted 35 resource observations in
  the current environment; two images contained no confident resource IDs.
  Evidence IDs, manifest paths, capture timestamps, image names, OCR text,
  and confidence are retained on observations. Owner matching is limited to
  identifiers found in the same visual row, and unowned OCR resources are
  excluded from activity-only linking. OCR additions did not change the 32-case
  sample metrics; screenshot extraction still needs labeled precision/recall
  testing before broader association rules are considered.

## Reproduction

From the repository root:

```powershell
python code\main.py --eval --mismatch-report
```
