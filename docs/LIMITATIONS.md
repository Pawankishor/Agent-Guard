# Known limitations, untested threat classes, deployment guidance

## What this milestone is not
Not production-ready, not proven secure, and not a complete defence against prompt injection. It is a measured foundation.
The benchmark (59 scenarios, 0 unauthorized side effects) was written by the same author as the defences; it is a regression suite and evidence of intended behaviour, not an independent red-team result.

## Limitations
1. **In-process capability gating is not a sandbox.** Hostile code in the same Python process can reach private names. Run tools in separate processes/containers (seccomp/gVisor, no network) for real isolation.
2. **Tool timeouts cannot kill threads.** A timed-out side-effecting call is reported `TIMEOUT` with `side_effect_performed=True` (outcome unknown).
3. **Detection is heuristic.** Paraphrased/multilingual/novel injections evade regex and the current ML model (measured: 3/16 and 1/16 on the adversarial set). Defence relies on authorization + provenance + approvals.
4. **Provenance matching is exact-substring** on string arguments; transformed values (re-encoded, paraphrased, split) can evade it.
5. **Audit log is tamper-evident, not tamper-proof.** An attacker with file access and the HMAC key can rewrite history; an attacker with file access but no key cannot forge a valid chain. Export to WORM storage.
6. **SQLite** serialises writers; fine for a single host, not for scale or multi-host. See the PostgreSQL path in ARCHITECTURE.md.
7. **Lockout can be abused** to lock a victim out (denial of service) - consider per-IP throttling and out-of-band unlock.
8. **No MFA, SSO, TLS termination or token binding**; session tokens are bearer secrets. Use an established IdP (OIDC/SAML) in production; `identity/` is the replaceable seam.
9. **Approval UX risks** (approval fatigue, social engineering of reviewers) are organisational, not technical.
10. **Risk weights are design choices, not calibrated probabilities.** Thresholds (50 points, 0.8 injection) are untuned.
11. **New-account handling** is a mild nudge; account provisioning (admin-only here) is the real control against identity switching. Sybil resistance beyond that is out of scope.
12. **Dashboard** is a client only; it adds no security. Rate-limit and protect it like any admin UI.
13. **Streamlit AppTest** smoke-tests rendering, not browser behaviour or XSS.
14. Demo `weather` is simulated; the live provider is implemented and egress-pinned but **not exercised against the real network** here.

## Threat classes not tested
Multi-turn/slow-burn injection, multimodal (image/PDF) injection, non-English attacks, model-extraction, timing/side channels (beyond equalised unknown-user login cost), supply-chain compromise of dependencies,
host compromise, DB-level adversaries with the HMAC key, real concurrency across processes/hosts, load/DoS testing, and any real LLM agent integration.

## Deployment guidance
- Set `AGENTGUARD_ENV=prod` and a 32-byte `AGENTGUARD_HMAC_KEY` from a secret manager; `scrypt_n >= 2^14` is enforced.
- Put an IdP in front; map identities to immutable `user_id`s; disable demo seeding.
- Run handlers out-of-process with no ambient credentials; keep real side effects (email, deletion, commands) disabled until reviewed.
- Move to PostgreSQL with INSERT-only audit/trust roles; ship audit to WORM; alert on `verify_chain` failure, `POLICY_UNAVAILABLE`, `RISK_ML_UNAVAILABLE`, bursts of `SUSPECTED_MALICIOUS`.
- Replace the authored corpus with reviewed real data before relying on any ML score; keep ML advisory.
- Independent security review and red-teaming before any production use.
