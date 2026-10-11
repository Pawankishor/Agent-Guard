# Developer guide

## Setup and commands
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                                  # unit + integration + adversarial tests
python -m agentguard.benchmark.run --out reports     # scenario benchmark -> reports/benchmark.md
python -m agentguard.ml.train --out reports/model_eval   # reproducible training + evaluation report
python scripts/seed_demo.py                          # demo users (random passwords -> data/demo_credentials.txt)
streamlit run dashboard/app.py
```
Library use (no Streamlit): see `tests/conftest.py`: build `AgentGuard(Settings(...))`, `provision_user`, `login`, then `submit_tool_call(token, ToolCallRequest(...))`.

## Register a tool
1. Write a handler `def run(args, env) -> json-serialisable` that touches only `env` resources (sandbox root, sandbox DB). Use parameterised SQL and fixed SQL maps; never build SQL or shell strings from arguments. Raise `ToolError(code)` for expected failures.
2. Write a resolver `def resolve(args, env) -> Resource(kind, "namespace:identifier", Sensitivity)` that classifies the **target** (resolve symlinks/paths here; raise `PathViolation` for escapes).
3. Declare strict `Field`s (type, max length, `pattern` that must fullmatch, enum choices, ranges). Prefer allow-list patterns.
4. Create the `ToolSpec(name="domain.action", risk_class=..., side_effect=..., reversible=..., timeout_s=...)` and `registry.register(spec)`.
5. Add permissions (below), then add tests: allowed, denied-without-side-effect, malicious args, and a benchmark scenario.
Rules: tool output is untrusted and is wrapped/scanned by the gateway; a tool must never call another tool or the network except through an allow-listed provider.

## Define permissions / add a policy
Edit `policy/engine.py::default_bundle()` or pass your own `PolicyBundle` to `AgentGuard(policy_bundle=...)`:
`Grant(tool, resource_glob, max_sensitivity, ALLOW|REQUIRE_APPROVAL)` per role, `Forbid(tool, resource_glob, roles)` for hard prohibitions, and `approvers[tool]` for who may approve.
Order within a role matters (first match wins). Bump `version`: pending approvals bound to the old version are invalidated. Default is deny.

## Add a detector
Implement `Detector` (`name`, `version`, `detect(DetectionInput) -> Sequence[Signal]`) and append it to the suite in `api/service.py`.
A detector returns signals only; it cannot grant permissions. Use `source="untrusted_content"` for anything derived from retrieved text so it is never downgraded.
Map new categories to risk rules in `risk/assess.py` (explicit rule + reason code + test). A crashing detector produces an error signal that escalates protected calls.
Pluggable model detectors implement the same interface (return a `Signal` with the calibrated probability as severity).

## Create an attack scenario
Add a function in `benchmark/scenarios.py` with `@sc(id, category, title, initial, request, expected, side=..., audit=..., malicious=..., unauth=...)`.
It receives a fresh `BenchEnv` (new DB + sandbox) and returns `Observed(decision, side_effect, leaked, ok)`. The runner checks decision, side effect, leak, extra check and expected audit event.
After adding scenarios run `python -m agentguard.benchmark.run --save-baseline` only when you have reviewed the results; regressions are reported against `benchmarks/baseline.json`.

## Model workflow (never automatic)
`train` -> `model_register` -> `model_gate` (fixed regression + adversarial suites, FPR limits, no regression vs active) -> `model_approve_and_activate` (human reviewer) -> `model_rollback` if needed.
Add reviewed examples via `submit_label` (human source + evidence required); add them to a **new versioned** dataset file, not in place.
