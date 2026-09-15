"""Figure for the tamper-resistance evaluation (Figure 14).

Panel (a): attack success rate per scenario - a well-defined question for all
           eight system/scenario cells, and honest that the chain does NOT
           stop an adversary who holds the owner key.
Panel (b): forensic reconstruction of the decision log after the adversary
           deletes the incriminating mirror rows.

Detection / attribution outcomes are reported in the LaTeX table emitted by
this script rather than as bars, because "detected" is undefined for an attack
that never succeeded (System C, scenario A2) and aggregate bars would compare
unequal denominators.

Usage: python3 experiments/generate_tamper_figure.py
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "results_tamper")
OUTS = [os.path.join(HERE, "..", "paper", "figures"),
        os.path.join(HERE, "..", "paper_fcds", "pics")]

BLUE, AQUA, INK, INK2 = "#2a78d6", "#1baf7a", "#0b0b0b", "#52514e"
plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 8, "axes.edgecolor": INK2, "axes.labelcolor": INK,
    "text.color": INK, "xtick.color": INK2, "ytick.color": INK2,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": "white", "axes.facecolor": "white",
})

truthy = lambda v: str(v).strip().lower() in ("true", "1", "yes")
rows = list(csv.DictReader(open(os.path.join(SRC, "tamper_results.csv"))))
recon = list(csv.DictReader(open(os.path.join(SRC, "reconstruction.csv"))))

SCEN = ["A1_insider_escalation", "A2_unauthorized_escalation",
        "A3_retroactive_revert", "A4_audit_log_tampering"]
SHORT = {"A1_insider_escalation": "A1\ninsider\nescalation",
         "A2_unauthorized_escalation": "A2\nunauthorized\nescalation",
         "A3_retroactive_revert": "A3\nretroactive\nrevert",
         "A4_audit_log_tampering": "A4\naudit-log\ntampering"}

def rate(sysname, sc, key):
    rs = [r for r in rows if r["scenario"] == sc and r["system"] == sysname]
    return 100.0 * sum(1 for r in rs if truthy(r[key])) / len(rs)

# Panel (a) of the earlier version showed attack success per scenario, but
# seven of its eight bars sat at 100% and the one informative cell (A2,
# System C blocked) is already the "Attack blocked" column of the tamper
# table. Only the forensic-reconstruction result is plotted here, sized for
# the text width so it needs no downscaling.
fig, ax2 = plt.subplots(figsize=(3.6, 2.5))
w = 0.36

mean = lambda s, k: sum(float(r[k]) for r in recon if r["system"] == s) \
                    / sum(1 for r in recon if r["system"] == s)
nw = float(recon[0]["attack_window_records"])
groups = ["All decision\nrecords", "Exploit-window\nrecords"]
bv = [mean("System_B", "reconstruction_pct"),
      100 * mean("System_B", "attack_window_recovered") / nw]
cv = [mean("System_C", "reconstruction_pct"),
      100 * mean("System_C", "attack_window_recovered") / nw]
x2 = np.arange(2)
q1 = ax2.bar(x2 - w/2, bv, w*0.94, color=BLUE, label="System B (centralized)")
q2 = ax2.bar(x2 + w/2, cv, w*0.94, color=AQUA, label="System C (blockchain)")
for bars in (q1, q2):
    for bar in bars:
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2.5,
                 f"{bar.get_height():.1f}", ha="center", va="bottom",
                 fontsize=7, color=INK)
ax2.set_ylim(0, 122); ax2.set_yticks([0, 25, 50, 75, 100])
ax2.set_ylabel("Recovered after tampering (%)")
ax2.set_xticks(x2, groups, fontsize=7.5)
ax2.grid(axis="y", color="#e6e5e0", linewidth=0.7); ax2.set_axisbelow(True)
ax2.legend(frameon=False, fontsize=7, loc="upper center",
           bbox_to_anchor=(0.5, -0.16), ncol=1)

fig.tight_layout()
for d in OUTS:
    if os.path.isdir(d):
        p = os.path.join(d, "figure14_tamper_resistance.png")
        fig.savefig(p, dpi=300, bbox_inches="tight")
        print("wrote", os.path.abspath(p))
plt.close(fig)

# ── LaTeX table: detection / attribution, with n.a. where attack was blocked ─
def cell(sysname, sc, key):
    rs = [r for r in rows if r["scenario"] == sc and r["system"] == sysname]
    if not any(truthy(r["attack_succeeded"]) for r in rs):
        return r"n.a."
    n = sum(1 for r in rs if truthy(r[key]))
    return r"\checkmark" if n == len(rs) else (r"$\times$" if n == 0 else f"{n}/{len(rs)}")

NAME = {"A1_insider_escalation": "A1 Insider escalation (owner key held)",
        "A2_unauthorized_escalation": "A2 Unauthorized escalation (no owner key)",
        "A3_retroactive_revert": "A3 Retroactive revert",
        "A4_audit_log_tampering": "A4 Audit-log tampering"}
L = [r"\begin{tabular}{|l|c|c|c|c|}", r"\hline",
     r"\bfseries Scenario / System & \bfseries Attack & \bfseries Detected by "
     r"& \bfseries Detected by & \bfseries Attributable \\",
     r" & \bfseries blocked & \bfseries state diff & \bfseries history audit & \\\hline"]
for sc in SCEN:
    L.append(r"\multicolumn{5}{|l|}{\itshape " + NAME[sc] + r"} \\\hline")
    for s, lab in (("System_B", "\\quad System B (centralized)"),
                   ("System_C", "\\quad System C (blockchain)")):
        rs = [r for r in rows if r["scenario"] == sc and r["system"] == s]
        blocked = r"\checkmark" if not any(truthy(r["attack_succeeded"]) for r in rs) else r"$\times$"
        L.append(f"{lab} & {blocked} & {cell(s,sc,'detect_state')} & "
                 f"{cell(s,sc,'detect_history')} & {cell(s,sc,'attributable')} \\\\\\hline")
L.append(r"\end{tabular}")
tbl = "\n".join(L)
open(os.path.join(SRC, "tamper_table.tex"), "w").write(tbl + "\n")
print("\nwrote", os.path.join(SRC, "tamper_table.tex"))
print("\n" + tbl)
