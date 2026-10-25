# Evaluation Report - Ghost Data Still Exists

## Automated sample evaluation

The deterministic evaluator in `code/main.py --eval` compares all 32 supplied
sample requests with `dataset/sample_output.csv`.

| Metric | Result |
| --- | ---: |
| Deletion-status accuracy | 32/32 (100%) |
| Exact output-row accuracy (status and full step objects) | 15/32 (46.9%) |
| Step precision | 0.99 |
| Step recall | 0.91 |
| Step F1 | 0.95 |
| Exact semantic step sequences (phase/system/resource/operation/state) | 16/32 |
| Exact full step arrays including evidence IDs | 15/32 |
| Evidence ID accuracy on matched steps | 175/176 |
| Account IDs matching sample expectations | 24 |
| Account IDs extra versus sample expectations | 1 |
| Expected account IDs not predicted | 8 |

The step-field precision/recall values are micro-averaged over semantic step
tuples: 176 true positives, 2 extra predicted tuples, and 17 expected tuples
not predicted. Evidence IDs are scored separately on matched semantic steps.
The exact-row metric compares deletion status and every step field, including
step number and evidence ID.
Running `python code\main.py --eval` prints each metric above directly from the
current implementation and `dataset/sample_output.csv`; the table is not a
manually entered result.

Account figures are a sample-output comparison, not independent proof that an
association is correct. The account matcher abstains when its status/time
candidate group is ambiguous; a one-case/one-resource group remains a
provisional heuristic association. Do not interpret expected-output agreement
as identity evidence.

All 16 non-exact semantic step sequences differ in their step sets; none are
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

## Failures found and improvements made

- **Ambiguous account association:** The earlier account linker paired
  status/time-compatible resources and cases by sorted order. Matching status
  and time establishes eligibility, not identity. It was replaced with
  conservative one-case/one-resource linking; ambiguous groups are left
  unresolved. A resource is also excluded from activity linking when its
  evidence explicitly resolves to a different user's identity.
- **Direct identity account recovery:** A uniquely identity-claimed account
  with a deletion-worker event inside the request window can be linked even
  when the identifying observation was captured after `audit_at`. Its state is
  still computed only from audit-eligible observations. This recovers
  `account_3866` for `case_27`; the matching pre-audit service export reports
  the account absent.
- **Expected-output account mismatches remain:** The sample comparison reports
  one extra account ID and eight expected IDs not predicted. Several of the
  missing accounts are in candidate groups shared by multiple requests; the
  available status/time evidence does not identify which user owns which
  resource. The remaining extra (`account_6523` for `case_17`) has a direct
  historical identifier match, but its deletion activity is outside the
  request window. These conflicts should not be "fixed" by positional pairing.
- **Missing analytics verifications:** The anonymized analytics rows have no
  remaining email, phone, or user reference. Their deletion activities and
  evidence bundles overlap multiple eligible sample requests, so the supplied
  data does not establish a unique user-to-resource association.
- **Missing retained audit verifications:** `audit_record_6645` and
  `audit_record_5569` do not appear in parsed evidence observations or
  `system_activity.csv`; there is no source-backed resource to verify for
  `case_18` or `case_20`.
- **Diagnostics obscured normal output:** Linking and trace diagnostics are
  gated behind `--debug-linking`, leaving the regular evaluator output concise.
- **Sequence score needs step-coverage work:** Since all non-exact sample arrays
  also differ in their step sets, the next improvement is evidence discovery
  and resource coverage, not changing the deterministic sort order.
- **Evidence citation discrepancy:** One matched sample step has an evidence
  ID different from the expected answer; citation selection should be reviewed
  separately from status and step-set evaluation.

## Reproduction

From the repository root:

```powershell
python code\main.py --eval
```
