"""Regenerate classifier figures (full 300-prompt data) and new figures for
the embedding end-to-end run and Sepolia validation.

Usage: python experiments/generate_paper_figures.py
Writes PNGs into paper/figures/.
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "paper", "figures")

BLUE = "#2a78d6"
AQUA = "#1baf7a"
INK = "#0b0b0b"
INK2 = "#52514e"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 7,
    "axes.edgecolor": INK2,
    "axes.labelcolor": INK,
    "text.color": INK,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
})


def bar_labels(ax, bars, fmt="{:.1f}", dy=1.0, fs=8.5):
    for b in bars:
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + dy,
                fmt.format(b.get_height()), ha="center", va="bottom",
                fontsize=fs, color=INK)


# ── Figure 10: classifier comparison (full 300-prompt offline evaluation) ────
def fig10():
    metrics = ["Accuracy", "Macro P", "Macro R", "Macro F1"]
    rule = [90.33, 93.48, 90.33, 90.58]
    emb = [96.67, 96.93, 96.67, 96.69]
    x = np.arange(len(metrics))
    w = 0.36
    fig, ax = plt.subplots(figsize=(5.0, 3.1))
    b1 = ax.bar(x - w / 2, rule, w * 0.94, color=BLUE, label="Rule-based (fail-closed)")
    b2 = ax.bar(x + w / 2, emb, w * 0.94, color=AQUA, label="Sentence-embedding (MiniLM-L6-v2)")
    bar_labels(ax, b1); bar_labels(ax, b2)
    ax.set_ylim(0, 112)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("Score (%)")
    ax.set_xticks(x, metrics)
    ax.grid(axis="y", color="#e6e5e0", linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8.5, loc="upper center",
              bbox_to_anchor=(0.5, -0.12), ncol=2)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "figure10_classifier_comparison.png"), dpi=300,
                bbox_inches="tight")
    plt.close(fig)


# ── Figure 11: embedding classifier confusion matrix (n=300) ─────────────────
def fig11():
    labels = ["search\n_web", "read\n_file", "transfer\n_money", "execute\n_command", "delete\n_database"]
    cm = np.array([
        [58, 2, 0, 0, 0],
        [0, 58, 0, 0, 2],
        [0, 0, 60, 0, 0],
        [0, 6, 0, 54, 0],
        [0, 0, 0, 0, 60],
    ])
    # sequential blue ramp (light -> dark)
    from matplotlib.colors import LinearSegmentedColormap
    ramp = LinearSegmentedColormap.from_list(
        "seqblue", ["#fcfcfb", "#cde2fb", "#86b6ef", "#3987e5", "#1c5cab", "#0d366b"])
    fig, ax = plt.subplots(figsize=(4.6, 4.0))
    ax.imshow(cm, cmap=ramp, vmin=0, vmax=60)
    for i in range(5):
        for j in range(5):
            v = cm[i, j]
            ax.text(j, i, str(v), ha="center", va="center", fontsize=9,
                    color="white" if v > 30 else (INK if v else "#b5b4ac"))
    ax.set_xticks(range(5), labels, fontsize=8)
    ax.set_yticks(range(5), labels, fontsize=8)
    ax.set_xlabel("Predicted action")
    ax.set_ylabel("Actual action")
    ax.spines[:].set_visible(False)
    ax.tick_params(length=0)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "figure11_confusion_matrix_embedding.png"), dpi=300)
    plt.close(fig)


# ── Figure 12: end-to-end System C, rule run vs embedding run ────────────────
def fig12():
    groups = ["Accuracy", "DENY-leakage"]
    rule_run = [73.00, 45.00]
    emb_run = [97.33, 3.33]
    x = np.arange(len(groups))
    w = 0.34
    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    b1 = ax.bar(x - w / 2, rule_run, w * 0.94, color=BLUE, label="Rule-based classifier run")
    b2 = ax.bar(x + w / 2, emb_run, w * 0.94, color=AQUA, label="Embedding classifier run")
    bar_labels(ax, b1, fmt="{:.2f}"); bar_labels(ax, b2, fmt="{:.2f}")
    ax.set_ylim(0, 112)
    ax.set_yticks([0, 25, 50, 75, 100])
    ax.set_ylabel("Rate (%)")
    ax.set_xticks(x, groups)
    ax.grid(axis="y", color="#e6e5e0", linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=8.5, loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "figure12_endtoend_embedding.png"), dpi=300)
    plt.close(fig)


# ── Figure 13: Sepolia read vs write latency ─────────────────────────────────
def fig13():
    reads_csv = os.path.join(HERE, "results_sepolia", "sepolia_reads.csv")
    writes_csv = os.path.join(HERE, "results_sepolia", "sepolia_writes.csv")
    reads = [float(r["latency_ms"]) for r in csv.DictReader(open(reads_csv))]
    writes = [float(r["total_ms"]) / 1000.0 for r in csv.DictReader(open(writes_csv))]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(5.1, 2.3))
    ax1.hist(reads, bins=12, color=BLUE, edgecolor="white", linewidth=0.8)
    ax1.set_xlabel("checkPermission read latency (ms)")
    ax1.set_ylabel("Count (n=50)")
    # same percentile convention as sepolia_summary.txt (lower element)
    med_r = sorted(reads)[int(np.ceil(0.5 * len(reads))) - 1]
    ax1.axvline(med_r, color=INK, linewidth=1, linestyle="--")
    ax1.text(med_r + 8, ax1.get_ylim()[1] * 0.92, f"median {med_r:.0f} ms",
             fontsize=8.5, color=INK)

    ax2.hist(writes, bins=12, color=AQUA, edgecolor="white", linewidth=0.8)
    ax2.set_xlabel("logDecision confirmation latency (s)")
    med_w = sorted(writes)[int(np.ceil(0.5 * len(writes))) - 1]
    ax2.axvline(med_w, color=INK, linewidth=1, linestyle="--")
    ax2.text(med_w + 0.6, ax2.get_ylim()[1] * 0.92, f"median {med_w:.1f} s",
             fontsize=8.5, color=INK)

    for ax in (ax1, ax2):
        ax.grid(axis="y", color="#e6e5e0", linewidth=0.7, zorder=0)
        ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "figure13_sepolia_latency.png"), dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    fig10(); fig11(); fig12(); fig13()
    print("figures written to", os.path.abspath(OUT))
