#!/bin/sh
# Moves the original prototype into legacy/ (history preserved) so nothing is lost, and removes only artifacts
# that are unsafe to keep loadable. Review before running; run from the repository root of your project.
set -eu
mkdir -p legacy
for f in agent.py app.py security.py tool.py train_model.py security_dashboard.py; do
  [ -f "$f" ] && git mv "$f" "legacy/$f"
done
# CSVs are kept for reference; the pickled model is NOT loadable by the new code and should not be executed.
for f in security_dataset.csv training_data.csv security_logs.csv; do
  [ -f "$f" ] && git mv "$f" "legacy/$f"
done
[ -f security_model.joblib ] && git mv security_model.joblib legacy/security_model.joblib.DO_NOT_LOAD
echo "Legacy files moved to legacy/. Then copy agentguard/, tests/, dashboard/, docs/, scripts/, requirements*.txt, pyproject.toml, .gitignore, .env.example into the repo root."
