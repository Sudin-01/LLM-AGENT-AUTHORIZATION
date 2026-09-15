"""
run_gemini_resume.py — resume an interrupted Gemini classifier evaluation.

The Gemini arm runs against a free-tier daily quota, so a full 300-prompt
sweep may not complete in one sitting. This harness makes the run RESUMABLE and
CHECKPOINTED:

  * it loads whatever rows already exist in the target CSV,
  * re-runs ONLY the trials that do not yet carry a genuine Gemini prediction
    (i.e. rows whose Classifier_Actually_Used is anything but "gemini"),
  * flushes the merged CSV to disk after EVERY prediction, so an interrupt or a
    quota wall costs at most one trial rather than the whole run.

An earlier 220-trial run was lost to exactly this failure mode; checkpointing
here is deliberate, not defensive decoration.

USAGE:
    GEMINI_API_KEY=... GEMINI_MODEL=gemini-3.5-flash-lite GEMINI_TIMEOUT_S=120 \
        python3 run_gemini_resume.py --out results_v2_gemini/classifier_comparison.csv \
                                     --seed results_v2_gemini/classifier_comparison_partial220.csv
"""
import argparse
import csv
import os
import sys
import time

from classifiers import get_classifier
from run_experiments import generate_prompts_v2

FIELDS = ["Trial_ID", "Target_Tool", "Prompt_Text", "Predicted_Tool",
          "Classifier_Name", "Classifier_Actually_Used", "Confidence",
          "Latency_ms", "Fallback_Reason", "Correct"]


def load(path: str) -> dict[int, dict]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, newline="") as fh:
        return {int(r["Trial_ID"]): r for r in csv.DictReader(fh)}


def flush(path: str, rows: dict[int, dict]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for tid in sorted(rows):
            w.writerow(rows[tid])
    os.replace(tmp, path)          # atomic: a crash mid-write cannot truncate the CSV


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="CSV to write/extend (the resumable checkpoint)")
    ap.add_argument("--seed", default="", help="optional CSV to seed from on first run")
    ap.add_argument("--classifier", default="gemini")
    ap.add_argument("--max", type=int, default=0, help="stop after N new predictions (0 = no limit)")
    args = ap.parse_args()

    rows = load(args.out) or load(args.seed)
    prompts = {p.trial_id: p for p in generate_prompts_v2()}

    todo = [tid for tid in sorted(prompts)
            if rows.get(tid, {}).get("Classifier_Actually_Used") != args.classifier]
    done = len(prompts) - len(todo)
    print(f"  dataset={len(prompts)}  already genuine={done}  to run={len(todo)}")
    if not todo:
        print("  nothing to do — run is already complete")
        return 0

    clf = get_classifier(args.classifier)
    warm = clf.classify("warm up the client before timing anything")  # never time a cold client
    if warm.classifier_used != args.classifier:
        # A misconfigured client silently answers via the rule-based fallback for
        # every trial, filling the CSV with rows that look like results but are
        # not. Refuse to start rather than manufacture 80 such rows.
        print(f"  ABORT: '{args.classifier}' is not answering "
              f"(got '{warm.classifier_used}', reason: {warm.fallback_reason}). "
              f"Nothing written.")
        return 2

    new = 0
    consecutive_fallback = 0
    for n, tid in enumerate(todo, 1):
        rec = prompts[tid]
        res = clf.classify(rec.prompt_text)
        rows[tid] = {
            "Trial_ID": tid,
            "Target_Tool": rec.target_tool,
            "Prompt_Text": rec.prompt_text,
            "Predicted_Tool": res.action_type,
            "Classifier_Name": args.classifier,          # requested
            "Classifier_Actually_Used": res.classifier_used,   # what actually answered
            "Confidence": res.confidence if res.confidence is not None else -1.0,
            "Latency_ms": res.latency_ms,
            "Fallback_Reason": res.fallback_reason or "",
            "Correct": res.action_type == rec.target_tool,
        }
        flush(args.out, rows)                            # checkpoint every single trial
        if res.classifier_used == args.classifier:
            new += 1
            consecutive_fallback = 0
        else:
            consecutive_fallback += 1
            if consecutive_fallback >= 5:
                print(f"  ABORT: 5 consecutive fallbacks "
                      f"(last reason: {res.fallback_reason}). "
                      f"Stopping so the quota wall is visible rather than silent.")
                break
        ok = "ok " if res.action_type == rec.target_tool else "MISS"
        print(f"  [{n}/{len(todo)}] id={tid:3d} {ok} {res.classifier_used:14s} "
              f"{rec.target_tool} -> {res.action_type} {res.fallback_reason or ''}")
        if args.max and new >= args.max:
            print(f"  stopping: reached --max {args.max}")
            break

    genuine = [r for r in rows.values() if r["Classifier_Actually_Used"] == args.classifier]
    corr = sum(1 for r in genuine if str(r["Correct"]) == "True")
    print(f"\n  genuine {args.classifier} predictions: {len(genuine)}/{len(prompts)}")
    if genuine:
        print(f"  accuracy over genuine predictions: {corr}/{len(genuine)} = {corr/len(genuine)*100:.2f}%")
    print(f"  checkpoint: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
