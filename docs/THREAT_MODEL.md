# Threat model

## Protected assets
1. Data behind tools (employee records, salaries, confidential files, secrets/canaries).
2. The ability to cause side effects (email egress, record changes, command requests).
3. Identity and session integrity; role assignments.
4. Audit-log integrity; trust-state integrity.
5. Model artifacts and policy bundles.
6. The system prompt / agent instructions (not modelled in this repo; the agent runtime is external).

## Trust boundaries
| Boundary | Untrusted side | Enforcement |
|---|---|---|
| Client -> API | Everything: role, name, urgency, purpose, claimed approval | Identity resolved server-side from session; client claims logged only |
| Agent -> gateway | The agent's proposed tool call and its reasoning | Strict schema, policy, provenance checks; agent has no direct handler access (capabilities) |
| Retrieved content / tool output -> agent | Documents, web pages, tool results | Marked untrusted, scanned, can never supply authority; content-derived arguments on side-effecting tools are blocked |
| Reviewer -> system | Reviewer actions | Separate role, no self-approval, evidence required |
| DB file | Anyone with file access | Hash chain (HMAC), signed approvals; *not* tamper-proof |

## Attackers
- A1 authenticated low-privilege user (privilege escalation, history evasion).
- A2 authenticated user attacking via prompts (direct injection, exfiltration requests).
- A3 external content author (indirect injection through documents/tool output).
- A4 malicious/compromised tool output.
- A5 insider with DB/file access (tampering, approval forgery).
- A6 unauthenticated caller (stolen/forged tokens, brute force).

## Entry points
`login`, `submit_tool_call`, `execute_approved`, `decide_approval`, review/label APIs, model-lifecycle APIs, dashboard, the database file, model artifacts.

## Threats and controls
| Threat | Control | Test evidence |
|---|---|---|
| Role/permission spoofing | Server-side role, re-read each call and at execution | `test_identity_and_policy.py`, benchmark S11/S12 |
| Identity reset by renaming | Trust keyed by `user_id` | benchmark S10 |
| Direct injection | Pattern + structural + normalisation; deny on high severity; policy independent | S13-S17 |
| Indirect injection / confused deputy | Provenance detector; deny content-derived side-effecting calls | S18, S19, `test_indirect_injection...` |
| Tool misuse via args | Strict schema, allow-listed commands, parameterised SQL, path containment | S22-S27 |
| Approval abuse | Bound HMAC-signed single-use approvals; reviewer != requester | S38-S44 |
| Replay / duplicate inflation | Unique (user, request_id); trust dedupe keys | S43 |
| Model failure / tampering | No default scores; hash-verified JSON; escalate protected ops | S31-S34 |
| Service outage | Fail closed; audit-before-side-effect | S35-S37 |
| Audit tampering | Append-only triggers + HMAC chain | `test_audit_chain_detects_tampering...` |
| Brute force | scrypt, lockout window | `test_lockout_and_password_rules` |

## Out of scope / assumptions
In-process isolation is not a security boundary; the host OS, Python runtime and dependency supply chain are trusted; the LLM/agent itself is untrusted
but not modelled; TLS, network egress control and secret management are deployment concerns; adaptive attackers who study the regexes are expected (see LIMITATIONS).
