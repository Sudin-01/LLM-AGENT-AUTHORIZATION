"""
run_classifier_comparison.py — BlockGuard Classifier Evaluation Harness
═══════════════════════════════════════════════════════════════════════════════
Evaluates one or more intent classifiers (rule-based, Gemini, and any future
classifier registered in classifiers.py) against the same 300-prompt labeled
dataset used in the main experiment, and reports standard ML classification
metrics: accuracy, precision, recall, F1 (macro + per-class), and a
confusion matrix.

This is intentionally DECOUPLED from run_experiment.py / the live API:
classification accuracy is a property of the classifier alone and does not
require Ganache, Flask, or the policy engine to be running. This keeps the
"focus only on the classification component" boundary clean — nothing here
touches policy enforcement.

USAGE:
    python run_classifier_comparison.py
    python run_classifier_comparison.py --classifiers rule gemini
    python run_classifier_comparison.py --n-per-tool 60

OUTPUT:
    classifier_comparison.csv       — per-trial predictions for every classifier
    classifier_metrics_report.txt   — accuracy/precision/recall/F1/confusion matrix
    confusion_matrix_<name>.png     — one heatmap per classifier (if matplotlib available)

REQUIREMENTS:
    pip install scikit-learn          (required — metrics computation)
    pip install matplotlib            (optional — confusion matrix plots)
    pip install google-genai          (optional — only if using --classifiers gemini)
"""

import argparse
import csv
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from classifiers import get_classifier, CANONICAL_TOOLS

try:
    from sklearn.metrics import (
        accuracy_score, precision_recall_fscore_support,
        confusion_matrix, classification_report,
    )
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Reuse the exact same labeled dataset as the main experiment, so classifier
# evaluation numbers are directly comparable to the enforcement-layer numbers
# already reported in the paper.
from run_experiments import (generate_prompts, generate_prompts_v2,
                             PromptRecord, TOOLS)


@dataclass
class ClassifierPrediction:
    trial_id:          int
    target_tool:       str   # ground truth
    prompt_text:       str
    predicted_tool:    str
    classifier_name:   str
    confidence:        float
    latency_ms:        float
    fallback_reason:   str
    correct:           bool


def evaluate_classifier(classifier_name: str, prompts: list[PromptRecord]) -> list[ClassifierPrediction]:
    print(f"\n{'─'*78}")
    print(f"  EVALUATING CLASSIFIER: {classifier_name}")
    print(f"{'─'*78}")

    clf = get_classifier(classifier_name)
    predictions = []
    t0 = time.perf_counter()

    for i, rec in enumerate(prompts):
        result = clf.classify(rec.prompt_text)
        predictions.append(ClassifierPrediction(
            trial_id=rec.trial_id,
            target_tool=rec.target_tool,
            prompt_text=rec.prompt_text,
            predicted_tool=result.action_type,
            classifier_name=result.classifier_used,  # actual classifier used (post-fallback)
            confidence=result.confidence if result.confidence is not None else -1.0,
            latency_ms=result.latency_ms,
            fallback_reason=result.fallback_reason or "",
            correct=(result.action_type == rec.target_tool),
        ))
        if (i + 1) % 50 == 0:
            print(f"  … {i+1}/{len(prompts)}")

    elapsed = time.perf_counter() - t0
    n_fallback = sum(1 for p in predictions if p.fallback_reason)
    print(f"  Done in {elapsed:.1f}s ({n_fallback} fallback(s) to rule-based)")
    return predictions


def compute_metrics(predictions: list[ClassifierPrediction], classifier_name: str) -> dict:
    y_true = [p.target_tool for p in predictions]
    y_pred = [p.predicted_tool for p in predictions]

    if not SKLEARN_AVAILABLE:
        # Manual fallback metrics if sklearn isn't installed
        accuracy = sum(1 for t, p in zip(y_true, y_pred) if t == p) / len(y_true)
        return {"accuracy": accuracy, "sklearn_available": False}

    accuracy = accuracy_score(y_true, y_pred)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=CANONICAL_TOOLS, average=None, zero_division=0
    )
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=CANONICAL_TOOLS, average="macro", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=CANONICAL_TOOLS)
    report_text = classification_report(y_true, y_pred, labels=CANONICAL_TOOLS, zero_division=0)

    return {
        "sklearn_available": True,
        "accuracy": accuracy,
        "macro_precision": macro_p,
        "macro_recall": macro_r,
        "macro_f1": macro_f1,
        "per_class": {
            tool: {"precision": precision[i], "recall": recall[i],
                  "f1": f1[i], "support": int(support[i])}
            for i, tool in enumerate(CANONICAL_TOOLS)
        },
        "confusion_matrix": cm.tolist(),
        "labels": CANONICAL_TOOLS,
        "classification_report_text": report_text,
    }


def plot_confusion_matrix(cm: list, labels: list, classifier_name: str, out_path: str):
    if not MATPLOTLIB_AVAILABLE:
        print(f"  ⚠ matplotlib not available — skipping confusion matrix plot for {classifier_name}")
        return

    cm = np.array(cm)
    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(cm, cmap="Blues")

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels([l.replace("_", "\n") for l in labels], fontsize=9)
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual (ground truth)")
    ax.set_title(f"Confusion Matrix — {classifier_name} classifier")

    thresh = cm.max() / 2
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            color = "white" if cm[i, j] > thresh else "black"
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", color=color, fontsize=11)

    fig.colorbar(im, ax=ax, shrink=0.8, label="Count")
    fig.tight_layout()
    fig.savefig(out_path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  ✓ Saved {out_path}")


def write_predictions_csv(all_predictions: dict, out_path: str = "classifier_comparison.csv"):
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "Trial_ID", "Target_Tool", "Prompt_Text", "Predicted_Tool",
            "Classifier_Name", "Classifier_Actually_Used", "Confidence", "Latency_ms",
            "Fallback_Reason", "Correct",
        ])
        writer.writeheader()
        for clf_label, preds in all_predictions.items():
            for p in preds:
                writer.writerow({
                    "Trial_ID": p.trial_id, "Target_Tool": p.target_tool,
                    "Prompt_Text": p.prompt_text, "Predicted_Tool": p.predicted_tool,
                    # Classifier_Name is what was *requested*. When the arm
                    # falls back, the prediction did not come from it, and
                    # recording only the request would misattribute the result.
                    "Classifier_Name": clf_label,
                    "Classifier_Actually_Used": (
                        "fallback" if p.fallback_reason else clf_label),
                    "Confidence": p.confidence,
                    "Latency_ms": p.latency_ms, "Fallback_Reason": p.fallback_reason,
                    "Correct": p.correct,
                })
    print(f"\n✓ Wrote predictions to {out_path}")


def write_metrics_report(all_metrics: dict, out_path: str = "classifier_metrics_report.txt"):
    lines = []
    lines.append("=" * 78)
    lines.append("  CLASSIFIER COMPARISON — METRICS REPORT")
    lines.append(f"  Generated: {datetime.now(timezone.utc).isoformat()}Z")
    lines.append(f"  sklearn available: {SKLEARN_AVAILABLE}")
    lines.append("=" * 78)

    for clf_name, metrics in all_metrics.items():
        lines.append(f"\n── {clf_name} " + "─" * (60 - len(clf_name)))
        lines.append(f"  Accuracy:        {metrics['accuracy']*100:.2f}%")
        if metrics.get("sklearn_available"):
            lines.append(f"  Macro Precision: {metrics['macro_precision']*100:.2f}%")
            lines.append(f"  Macro Recall:    {metrics['macro_recall']*100:.2f}%")
            lines.append(f"  Macro F1:        {metrics['macro_f1']*100:.2f}%")
            lines.append(f"\n  Per-class breakdown:")
            for tool, m in metrics["per_class"].items():
                lines.append(f"    {tool:18} precision={m['precision']*100:6.2f}%  "
                             f"recall={m['recall']*100:6.2f}%  f1={m['f1']*100:6.2f}%  "
                             f"(n={m['support']})")
            lines.append(f"\n  Confusion matrix (rows=actual, cols=predicted):")
            lines.append(f"    {'':18}" + "".join(f"{l[:8]:>10}" for l in metrics["labels"]))
            for i, row in enumerate(metrics["confusion_matrix"]):
                lines.append(f"    {metrics['labels'][i]:18}" + "".join(f"{v:>10}" for v in row))

    lines.append("\n" + "=" * 78)
    report = "\n".join(lines)

    with open(out_path, "w") as f:
        f.write(report)
    print(f"✓ Wrote metrics report to {out_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description="BlockGuard classifier comparison harness")
    parser.add_argument("--classifiers", nargs="+", default=["rule", "gemini"],
                       help="Which classifiers to evaluate (default: rule gemini)")
    parser.add_argument("--n-per-tool", type=int, default=60)
    parser.add_argument("--dataset", choices=["v1", "v2"], default="v2",
                        help="v2 = curated 300-prompt set (default)")
    args = parser.parse_args()

    if not SKLEARN_AVAILABLE:
        print("⚠ scikit-learn not installed — falling back to accuracy-only metrics.")
        print("  Install with: pip install scikit-learn")

    prompts = (generate_prompts_v2() if args.dataset == "v2"
               else generate_prompts(n_per_tool=args.n_per_tool))
    print(f"✓ Generated {len(prompts)} labeled prompts "
         f"(same dataset as run_experiment.py — fixed seed)")

    all_predictions = {}
    all_metrics = {}

    for clf_name in args.classifiers:
        predictions = evaluate_classifier(clf_name, prompts)
        all_predictions[clf_name] = predictions
        metrics = compute_metrics(predictions, clf_name)
        all_metrics[clf_name] = metrics

        if metrics.get("sklearn_available"):
            plot_confusion_matrix(
                metrics["confusion_matrix"], metrics["labels"], clf_name,
                f"confusion_matrix_{clf_name}.png",
            )

    write_predictions_csv(all_predictions)
    report = write_metrics_report(all_metrics)
    print("\n\n" + report)


if __name__ == "__main__":
    main()
