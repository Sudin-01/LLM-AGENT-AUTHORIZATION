#!/usr/bin/env bash
# ============================================================================
#  BlockGuard - full reproduction pipeline
#
#  Runs every experiment reported in the paper from a clean chain and then
#  verifies the resulting numbers against the manuscript.
#
#    ./scripts/reproduce.sh              # everything (~15 min)
#    ./scripts/reproduce.sh sweeps       # main sweeps only
#    ./scripts/reproduce.sh verify       # re-check numbers from existing CSVs
#
#  Environment:
#    PYTHON   interpreter with experiments/requirements.txt installed
#    NODE     node binary (>=18) providing ganache / npx
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
GANACHE_PORT=8545
API_PORT=5000
API="http://127.0.0.1:${API_PORT}"
MNEMONIC="test test test test test test test test test test test junk"
LOGDIR="$ROOT/.reproduce-logs"; mkdir -p "$LOGDIR"

BACKEND_PID=""; GANACHE_PID=""
cleanup() {
  [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true
  [ -n "$GANACHE_PID" ] && kill "$GANACHE_PID" 2>/dev/null || true
}
trap cleanup EXIT

step()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()    { printf '   \033[32mok\033[0m %s\n' "$*"; }
die()   { printf '   \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

wait_for() {  # wait_for <url> <label> <tries>
  for _ in $(seq 1 "${3:-40}"); do
    curl -s -m 2 "$1" >/dev/null 2>&1 && { ok "$2 ready"; return 0; }
    sleep 3
  done
  die "$2 did not come up (see $LOGDIR)"
}

preflight() {
  step "Preflight"
  command -v "$PYTHON" >/dev/null || die "PYTHON=$PYTHON not found"
  "$PYTHON" - <<'PY' || exit 1
import sys
missing = []
for m in ("requests", "web3", "numpy", "sklearn", "matplotlib"):
    try: __import__(m)
    except ImportError: missing.append(m)
if missing:
    print("   missing python packages:", ", ".join(missing))
    print("   install with: python -m pip install -r experiments/requirements.txt")
    sys.exit(1)
print(f"   python {sys.version.split()[0]} with required packages")
PY
  command -v npx >/dev/null || die "npx not found (need Node >= 18)"
  command -v ganache >/dev/null || die "ganache not found (npm i -g ganache)"
  ok "toolchain present"
}

start_chain() {
  step "Starting a fresh local chain"
  pkill -f "ganache --wallet.mnemonic" 2>/dev/null || true; sleep 1
  ganache --wallet.mnemonic "$MNEMONIC" --chain.chainId 1337 \
          --port "$GANACHE_PORT" --wallet.totalAccounts 10 \
          > "$LOGDIR/ganache.log" 2>&1 &
  GANACHE_PID=$!
  for _ in $(seq 1 30); do
    curl -s -m 2 -X POST "http://127.0.0.1:${GANACHE_PORT}" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
      >/dev/null 2>&1 && { ok "chain up on :$GANACHE_PORT"; return; }
    sleep 2
  done
  die "ganache did not start"
}

deploy() {  # re-seeds the baseline policy; safe to call repeatedly
  step "Deploying contract and seeding baseline policy"
  find contracts scripts test -name '._*' -delete 2>/dev/null || true
  npx hardhat run scripts/deploy.js --network ganache > "$LOGDIR/deploy.log" 2>&1 \
    || { cat "$LOGDIR/deploy.log"; die "deploy failed"; }
  ok "$(grep -o '0x[0-9a-fA-F]\{40\}' "$LOGDIR/deploy.log" | head -1)"
}

start_backend() {  # start_backend <classifier>
  step "Backend (CLASSIFIER_TYPE=$1)"
  pkill -f "$ROOT/backend/app.py" 2>/dev/null || true
  pkill -f "app.py" 2>/dev/null || true; sleep 2
  ( cd backend && USE_TF=0 TOKENIZERS_PARALLELISM=false CLASSIFIER_TYPE="$1" \
      "$PYTHON" app.py > "$LOGDIR/backend-$1.log" 2>&1 & echo $! > "$LOGDIR/backend.pid" )
  BACKEND_PID="$(cat "$LOGDIR/backend.pid")"
  wait_for "$API/api/health" "backend"
}

stop_backend() { [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null || true; BACKEND_PID=""; sleep 2; }

sweep() {  # sweep <classifier> <outdir>
  step "900-trial sweep - $1 classifier -> experiments/$2"
  mkdir -p "experiments/$2"
  ( cd "experiments/$2" && USE_TF=0 "$PYTHON" ../run_experiments.py --dataset v2 ) \
      2>&1 | tee "$LOGDIR/sweep-$1.log" | grep -E "preconditions|accuracy|leakage rate|✗" || true
  grep -q "Summary written" "$LOGDIR/sweep-$1.log" || die "sweep ($1) did not complete"
  ok "sweep complete"
}

run_sweeps() {
  deploy;            start_backend rule;      sweep rule results_v2_rule;  stop_backend
  deploy;            start_backend embedding; sweep embedding results_v2;  stop_backend
}

run_ablation() {
  step "Policy ablation (3 configurations)"
  deploy; start_backend rule
  mkdir -p experiments/results_v2_ablation
  ( cd experiments/results_v2_ablation && USE_TF=0 "$PYTHON" ../run_ablation.py --dataset v2 ) \
      > "$LOGDIR/ablation.log" 2>&1 || die "ablation failed"
  grep -E "System_[BC]: accuracy" "$LOGDIR/ablation.log" | head -6
  stop_backend
  ok "ablation complete (leaves policy dirty; next deploy re-seeds)"
}

run_offline() {
  step "Offline classifier comparison + dataset diversity audit"
  mkdir -p experiments/results_v2_clf
  ( cd experiments/results_v2_clf && USE_TF=0 "$PYTHON" ../run_classifier_comparison.py \
       --dataset v2 --classifiers rule embedding ) > "$LOGDIR/clf.log" 2>&1 || die "classifier comparison failed"
  grep -E "Accuracy:" "$LOGDIR/clf.log" | head -2
  USE_TF=0 "$PYTHON" experiments/audit_dataset_diversity.py > "$LOGDIR/diversity.log" 2>&1 \
      || die "diversity audit failed"
  grep -E "distinct sentence patterns|near-duplicate pairs" "$LOGDIR/diversity.log" | head -4

  # LLM projection check. This validates the conformance projection against every live
  # sweep before reporting it, and exits non-zero if any of the four measured
  # figures fails to reproduce -- the paper cites that guarantee, so it must
  # actually run here rather than only on demand.
  USE_TF=0 "$PYTHON" experiments/analyze_m3_gemini.py > "$LOGDIR/llm_projection.log" 2>&1 \
      || die "LLM projection check failed (projection did not validate -- see $LOGDIR/llm_projection.log)"
  grep -E "^  \[(OK|FAIL)\]" "$LOGDIR/llm_projection.log"
  grep -E "^  (gemini|embedding|rule) " "$LOGDIR/llm_projection.log" | head -3
  ok "offline analyses complete"
}

run_opa() {
  step "System E: Open Policy Agent external comparator"
  if ! command -v opa >/dev/null; then
    printf '   skipped: opa not installed (brew install opa)\n'; return 0
  fi
  "$PYTHON" experiments/run_opa_experiment.py > "$LOGDIR/opa.log" 2>&1 || die "OPA run failed"
  grep -E "conformance|latency  median|escalation succeeded|detected by" "$LOGDIR/opa.log"
  ok "OPA comparator complete"
}

run_tamper() {
  step "Tamper-resistance evaluation (fresh chain for comparable audit timings)"
  deploy
  "$PYTHON" experiments/run_tamper_experiment.py > "$LOGDIR/tamper.log" 2>&1 || die "tamper run failed"
  grep -E "System_[BC]:  overall records" "$LOGDIR/tamper.log"
  ok "tamper evaluation complete"
}

verify() {
  step "Verifying every reported number against the manuscript"
  "$PYTHON" experiments/verify_paper_numbers.py | tail -4
}

figures() {
  step "Regenerating figures"
  for g in regenerate_all_figures generate_v2_figures generate_tamper_figure generate_paper_figures; do
    "$PYTHON" "experiments/$g.py" > "$LOGDIR/fig-$g.log" 2>&1 && ok "$g" || die "$g failed"
  done
}

case "${1:-all}" in
  all)      preflight; start_chain; run_sweeps; run_ablation; run_offline; run_opa; run_tamper; verify; figures ;;
  sweeps)   preflight; start_chain; run_sweeps; verify ;;
  ablation) preflight; start_chain; run_ablation ;;
  tamper)   preflight; start_chain; run_tamper ;;
  offline)  preflight; run_offline ;;
  opa)      run_opa ;;
  gemini)   preflight
            [ -n "${GEMINI_API_KEY:-}" ] || die "set GEMINI_API_KEY to re-run the LLM classifier arm"
            step "LLM classifier arm (300 prompts, resumable)"
            ( cd experiments && USE_TF=0 GEMINI_MODEL="${GEMINI_MODEL:-gemini-3.5-flash-lite}" \
                GEMINI_TIMEOUT_S="${GEMINI_TIMEOUT_S:-120}" "$PYTHON" run_gemini_resume.py \
                --out results_v2_gemini/classifier_comparison.csv ) || die "gemini arm failed"
            run_offline ;;
  verify)   verify ;;
  figures)  figures ;;
  *) echo "usage: $0 [all|sweeps|ablation|offline|gemini|opa|tamper|verify|figures]"; exit 2 ;;
esac

printf '\n\033[1mDone.\033[0m Logs in %s\n' "$LOGDIR"
