#!/bin/bash
#SBATCH --job-name=ipi-stage-a
#SBATCH --partition=gpu.L40S
#SBATCH --gres=gpu:1
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=64G
#SBATCH --time=08:00:00
#SBATCH --output=logs/%x-%j.out
#SBATCH --error=logs/%x-%j.err
set -euo pipefail
WORK="${SLURM_SUBMIT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
cd "$WORK"
export HF_HOME="$WORK/hf_cache"
export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
EXTRA=()
if [[ -n "${LIMIT:-}" ]]; then EXTRA=(--limit "$LIMIT"); fi
.venv/bin/python run.py --stage stages/A.json --split "${SPLIT:-development}" \
  --reps "${REPS:-3}" --out "${OUT:-results/stage-a-development.jsonl}" "${EXTRA[@]}"
