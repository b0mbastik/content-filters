#!/bin/bash -l
#SBATCH --job-name=ipi-stage-a
#SBATCH --partition=gpu.L40S
#SBATCH --gres=gpu:1
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --mem=64G
#SBATCH --time=00:30:00
#SBATCH --output=logs/%x-%j.out
#SBATCH --error=logs/%x-%j.err
set -euo pipefail
WORK="${SLURM_SUBMIT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
cd "$WORK"
if [[ -z "${PYTHON:-}" ]]; then
  module load python/3.12.12
  PYTHON=.venv-nemo/bin/python
fi
export HF_HOME="$WORK/hf_cache"
export HF_HUB_OFFLINE=1
export TOKENIZERS_PARALLELISM=false
EXTRA=()
if [[ -n "${LIMIT:-}" ]]; then EXTRA=(--limit "$LIMIT"); fi
if [[ -n "${OUT:-}" ]]; then EXTRA+=(--out "$OUT"); fi
if [[ "${INPUT_GUARDRAIL:-0}" == 1 ]]; then EXTRA+=(--input-guardrail); fi
"$PYTHON" run.py --stage "${STAGE:-stages/A.json}" \
  --reps "${REPS:-3}" "${EXTRA[@]}"
