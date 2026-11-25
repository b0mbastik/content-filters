#!/usr/bin/env bash
# Submit the Category 2 clean baseline using the shared Slurm GPU job.
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "$repo_dir"
mkdir -p logs

export STAGE=stages/category_2_baseline.json
export REPS=3
export LIMIT=0
export INPUT_GUARDRAIL=0
export OUT="${OUT:-results/stage-category-2-baseline.jsonl}"

exec sbatch --parsable --job-name=ipi-category-2-clean --export=ALL job.sh
