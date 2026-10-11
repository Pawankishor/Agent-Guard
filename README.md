# AgentGuard: context-aware runtime trust and security framework for AI agents

A modular, testable runtime protection layer that sits between an AI agent and its tools. It authenticates the caller, evaluates deterministic policy,
detects injection and anomalous behaviour, tracks per-identity trust, requires bound human approval for high-impact actions, executes tools through a single gateway, and records an auditable trail.

**Status: an engineering foundation with measured results on its own test suite. Not production-ready; not proven secure. See `docs/LIMITATIONS.md`.**

## Quick start
```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m agentguard.benchmark.run --out reports
python scripts/seed_demo.py && streamlit run dashboard/app.py
```

## Results from this repository (2026-10-11 sandbox run)
| Check | Result |
|---|---|
| Test suite | 120 passed (unit, integration, adversarial, ML lifecycle, dashboard smoke) |
| Mutation spot-check, 15 distinct mutants of security-critical guards | 14 caught; 1 (policy outage treated as allow) is masked by execution-time revalidation, with the same safe outcome. The first sweep exposed 3 gaps; 5 tests were added |
| Benchmark | 59/59 scenarios, 20/20 categories; attack success 0/27; unauthorized side effects 0; benign false positives 0/14; gateway p50 ~14 ms, p95 ~23 ms (sandbox, scrypt 2^10) |
| ML advisory model | At its gated threshold: recall 0.00 (held-out) and 0.06 (adversarial). **Not useful as a detector yet**; regex baseline recall 0.19 on adversarial. See `docs/MODEL_EVALUATION.md` |

The scenarios were written by the same author as the defences: treat them as a regression suite, not independent validation.

## Layout
`agentguard/` library (identity, policy, tools, detection, trust, risk, execution, audit, ml, agent, api, benchmark) · `dashboard/` Streamlit client · `tests/` · `docs/` · `scripts/`.

## Documents
`docs/AUDIT.md` (original-project audit + migration) · `docs/THREAT_MODEL.md` · `docs/ARCHITECTURE.md` · `docs/DEVELOPER_GUIDE.md` · `docs/MODEL_EVALUATION.md` · `docs/LIMITATIONS.md` · `docs/PHASE_REPORT.md`.
