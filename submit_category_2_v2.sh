#!/usr/bin/env bash
# Submit the Category 2 version-2 injection matrix on Hypatia.
#
# Crosses the four clean Category 2 reports (UC-02, UC-03, UC-13, UC-16) with
# all six version-2 injection fixtures (injections_v2/) under the three system
# prompt levels P0/P1/P2 (stages A/B/C). Each report is run in BASE (clean)
# and I (injected) conditions, so the BASE rows are the clean baseline and the
# I rows are the injection trials.
#
# Full run: 4 reports x 6 injections = 24 scenarios; each in BASE + I across
#           P0/P1/P2, 3 reps = 24 x 2 x 3 x 3 = 432 model calls.
#
# Usage:
#   ./submit_category_2_v2.sh                 # full run, 3 reps
#   REPS=1 LIMIT=1 ./submit_category_2_v2.sh  # smoke test (12 calls)
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$repo_dir"
mkdir -p logs

export STAGE=stages/category_2_v2.json
export REPS="${REPS:-3}"
export LIMIT="${LIMIT:-0}"
export INPUT_GUARDRAIL=0
export OUT="${OUT:-results/stage-category-2-v2.jsonl}"

exec sbatch --parsable --job-name=ipi-category-2-v2 --export=ALL job.sh
