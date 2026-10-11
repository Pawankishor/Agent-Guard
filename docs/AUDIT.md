# Phase 1: Audit of the original project

Repository audited: `sagarpp-hub/project` (cloned with `git clone`; all `.py` files read in full; CSVs sampled).
Audit date: 2026-10-11. Evidence tags: **[EXEC]** reproduced by running the original code in a scratch copy,
**[CODE]** confirmed by reading the source, **[DESIGN]** a risk that follows from the design but was not demonstrated.

> Caveat on method: importing the original `security.py` unpickles `security_model.joblib` (finding F-05). I did this
> in a throw-away sandbox to establish the baseline. Do not load that file on a machine you care about unless you trust its provenance.

## 1. Current request-execution flow (as found)

```mermaid
flowchart TD
  U[Streamlit UI: user types NAME, picks ROLE, urgency, purpose from widgets] --> A[app.py: regex prompt-injection check (copy #1)]
  A --> C[agent.py classify_request: keyword -> tool, first match wins]
  C --> H[history lookup: security_logs.csv filtered by NAME text]
  H --> S[security.py security_check: heuristic weights + RandomForest ml_risk + regex (copy #2)]
  S -->|ml failure| F[ml_risk silently = 50]
  S --> D{decision ALLOW / HUMAN APPROVAL / DENY}
  D -->|approval| B[Approve button in st.session_state, same user can click]
  D --> T[tool.py: get_weather etc. called directly from UI code]
  T --> L[append row to security_logs.csv]
```

## 2. File-by-file

| File | Role | Main issues |
|---|---|---|
| `app.py` | UI + orchestration + a second prompt-injection regex | Role/name/urgency/purpose come from widgets; history keyed by name; approval is a UI button; executes tools directly; detector duplicated and divergent from `security.py` |
| `security.py` | Risk engine | Loads `.joblib` at import with no integrity check; arbitrary weights; inference failure -> 50; regex only; previous DENY counted as suspicious |
| `agent.py` | Keyword intent classifier | First match wins; one sentence can hide a destructive intent behind a benign one |
| `tool.py` | Tool implementations | No authorization or schema validation; weather ignores `city` |
| `train_model.py` | Synthetic data + Random Forest | Labels are a hand-written rule of the features; unreachable branch; random split; overwrites dataset and model in place |
| `security_dashboard.py` | Log viewer | Reads CSV directly; no analyst workflow, no integrity |
| `*.csv`, `*.joblib` | Data/model | `training_data.csv` has a stale 7-column schema; logs have blank fields and unverified user-chosen values |

## 3. Findings

| ID | Sev | Status | Finding | Evidence | Exploit conditions | Remediation (where) |
|---|---|---|---|---|---|---|
| F-01 | Critical | [CODE][EXEC] | Role is a UI-selected string | Role comes from a selectbox; `security_logs.csv` shows the same user (`student1`) as both *Student* and *Employee*; 2 of 9 users in the log have multiple roles | Anyone with access to the page | Server-side roles, resolved on every call (`identity/service.py`); test `test_client_supplied_role_cannot_grant_privilege` |
| F-02 | High | [CODE] | History keyed by editable display name | Log lookups filter on the `User` text | Type a new name to reset history | History keyed by immutable `user_id` (`trust/engine.py`); test `test_changing_display_name_or_username_does_not_reset_trust` |
| F-03 | High | [CODE] | Approval is a same-user UI button, not bound to the operation | Approval state in `st.session_state`; no requester/approver separation, args hash, expiry or single use | The requester clicks approve; modify args after approval | `execution/approvals.py` (HMAC-signed, bound, single-use, separate reviewer); `tests/test_approvals.py` |
| F-04 | High | [EXEC] | Silent fallback `ml_risk=50` on inference failure; low-impact tools then ALLOW | With a broken model: Read File, Search Database, Send Email all returned **ALLOW** | Any model/dependency failure | No default score; unavailable ML escalates protected ops (`risk/assess.py`); tests `test_missing_or_broken_model...` |
| F-05 | High | [CODE] | `joblib.load` of a repo artifact at import, no integrity check | Pickle deserialisation executes code | Tampered/untrusted artifact | JSON-only artifacts + SHA-256 registry check (`ml/model.py`, `ml/registry.py`) |
| F-06 | High | [EXEC] | Regex-only injection detection, two diverging copies (`app.py` vs `security.py`) | 7/9 trivial evasions missed (leetspeak, zero-width, hyphenation, paraphrase); 3/5 benign sentences flagged | Anyone | Layered detectors + provenance + policy independent of detection (`detection/`) |
| F-07 | High | [CODE] | No authorization at the tool boundary | `tool.py` functions are plain callables; UI calls them | Any code path that skips the UI checks | Single gateway, capability-gated handlers (`execution/`) - **in-process defence in depth only; see LIMITATIONS** |
| F-08 | Medium | [CODE] | Keyword classifier: first match wins, so "read report.txt and delete everything" is classified as a read | Branch order in `classify_request` | Multi-intent sentences | Planner returns all intents; each is authorised separately (`agent/planner.py`) |
| F-09 | Medium | [CODE][EXEC] | `get_weather(city)` ignores `city`; always queries Bengaluru coordinates | Hard-coded lat/lon | Every non-Bengaluru query returns wrong data | Providers honour the city; unknown city is an error (`tools/weather.py`) |
| F-10 | Medium | [EXEC] | Reported ML accuracy reflects the rule that generated the labels | 93.4% accuracy on its own held-out slice, but positives are 86.8% of rows and a **depth-4 decision tree reaches 89.4%** on the same labels | n/a | Authored scenario corpus, family-grouped splits, regex baseline in every report (`ml/`) |
| F-11 | Low | [CODE] | Unreachable branch: `request_count >= 35` after `>= 20` | Source | n/a | Removed with the generator |
| F-12 | Low | [EXEC] | Incoherent synthetic scenarios (11.9% pair *Weather API* with Delete/Execute/Write/Update/Send) | Dataset | n/a | Not carried over |
| F-13 | Medium | [CODE] | Earlier DENY decisions are counted as suspicious history | Failed-request counting reads DENY rows | Honest users who hit permission walls get punished | Typed events, tiny capped weight for ordinary denials (`trust/engine.py`); test `test_repeated_ordinary_denials...` |
| F-14 | Medium | [CODE][DATA] / [DESIGN] | CSV logging: no integrity, no locking, user-chosen fields recorded as fact, blank `Request` fields | Log head | Concurrent writes or edits; concurrency corruption **not demonstrated** | SQLite WAL + hash-chained append-only audit (`audit/log.py`) |
| F-15 | Medium | [CODE] | No model versioning, rollback, regression gate; training overwrites files in place | `train_model.py` | n/a | `ml/registry.py` lifecycle |
| F-16 | Info | [EXEC] | `training_data.csv` has a stale schema that does not match the generator | Header | n/a | Not carried over |
| F-17 | Info | [CODE] | No automated tests; no dependency manifest observed | Repository listing | n/a | `tests/`, `requirements*.txt` |

### Concerns from the brief that were *not* confirmed as vulnerabilities
- "Possible overlap between training and evaluation scenarios": the legacy split is a random row split of a combinatorial
  space; I did not measure exact-duplicate overlap beyond confirming the label is a function of the features (F-10). Treated as a design risk.
- Logging concurrency (F-14) is a design risk; I did not reproduce corruption.

## 4. Baseline results (original code, sandbox)
See the commands in `docs/PHASE_REPORT.md`. Headline numbers are the ones in the table above.

## 5. Dependency and configuration review
No manifest or lock file was observed (`F-17`); scikit-learn pickles are version-sensitive and the artifact loaded under
scikit-learn 1.8.0 in the sandbox, but there is no guarantee of that elsewhere. No secrets were observed in source, but the original
design has no place for any (no auth) - so none were needed and none were protected.

## 6. Migration plan (nothing useful is thrown away)
- **Kept, reimplemented:** keyword planner (now multi-intent, untrusted), weather tool (now correct), Random Forest idea (now a hashed linear baseline measured against regex), Streamlit UI (now a client of authorised APIs), logs (now a database).
- **Moved to `legacy/`, not deleted:** `scripts/migrate_legacy.sh` performs `git mv` of the old modules. Do not run `security_model.joblib`; it is superseded.
- **Removed, with reasons:** the pickle model (F-05), synthetic generator (F-10/F-12), CSV logs (F-14).
