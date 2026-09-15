"""Figures for the v2 curated-dataset sweep.

figure15_dataset_diversity.png : v1 vs v2 prompt-set diversity
figure16_stratum_accuracy.png  : per-stratum accuracy and System C error modes
"""
import csv, os
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUTS = [os.path.join(HERE, "..", "paper", "figures"),
        os.path.join(HERE, "..", "paper_fcds", "pics")]
BLUE, AQUA, RED, INK, INK2 = "#2a78d6", "#1baf7a", "#e34948", "#0b0b0b", "#52514e"
plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman","Times","DejaVu Serif"],
    "font.size": 7, "axes.edgecolor": INK2, "axes.labelcolor": INK, "text.color": INK,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
    "axes.spines.right": False, "figure.facecolor": "white", "axes.facecolor": "white",
})
TOOLS = ["search_web","read_file","transfer_money","execute_command","delete_database"]
MAP = {"APPROVED":"ALLOW","BLOCKED":"DENY","DENIED":"DENY","ALLOW":"ALLOW","DENY":"DENY"}
norm = lambda s: MAP.get(s.strip().upper(), s.strip().upper())
ok = lambda r: norm(r["Permission_Decision"]) == norm(r["Intended_Policy"])

def save(fig, name):
    for d in OUTS:
        if os.path.isdir(d):
            p = os.path.join(d, name)
            fig.savefig(p, dpi=300, bbox_inches="tight"); print("wrote", os.path.abspath(p))
    plt.close(fig)

def lab(ax, bars, fmt="{:.0f}", dy=1.5, fs=8.5):
    for b in bars:
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+dy, fmt.format(b.get_height()),
                ha="center", va="bottom", fontsize=fs, color=INK)

# ── Figure 15: dataset diversity ───────────────────────────────────────────
div = list(csv.DictReader(open(os.path.join(HERE,"results_dataset_v2","diversity_audit.csv"))))
d1 = {r["tool"]: r for r in div if r["dataset"].startswith("v1")}
d2 = {r["tool"]: r for r in div if r["dataset"].startswith("v2")}

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(9.2, 3.3))
x, w = np.arange(len(TOOLS)), 0.36
b1 = ax1.bar(x-w/2, [int(d1[t]["unique_patterns"]) for t in TOOLS], w*0.94,
             color=BLUE, label="v1 template expansion")
b2 = ax1.bar(x+w/2, [int(d2[t]["unique_patterns"]) for t in TOOLS], w*0.94,
             color=AQUA, label="v2 curated")
lab(ax1, b1); lab(ax1, b2)
# 60 is the maximum attainable (60 prompts per tool); stated in the caption
ax1.axhline(60, color=INK2, lw=0.9, ls="--")
ax1.set_ylim(0, 72); ax1.set_ylabel("Distinct sentence patterns")
ax1.set_xticks(x, [t.replace("_","\n") for t in TOOLS], fontsize=8)
ax1.grid(axis="y", color="#e6e5e0", lw=0.7); ax1.set_axisbelow(True)
ax1.legend(frameon=False, fontsize=8.5, loc="upper center",
           bbox_to_anchor=(0.5,-0.20), ncol=2)
ax1.set_title("(a) Distinct sentence patterns behind 60 prompts", fontsize=9.5, pad=8)

nd1 = [int(d1[t]["near_dupes"]) for t in TOOLS]
nd2 = [int(d2[t]["near_dupes"]) for t in TOOLS]
c1 = ax2.bar(x-w/2, nd1, w*0.94, color=BLUE); c2 = ax2.bar(x+w/2, nd2, w*0.94, color=AQUA)
lab(ax2, c1, dy=0.8); lab(ax2, c2, dy=0.8)
ax2.set_ylim(0, max(nd1)*1.25); ax2.set_ylabel("Near-duplicate pairs\n(cosine $\\geq$ 0.95)")
ax2.set_xticks(x, [t.replace("_","\n") for t in TOOLS], fontsize=8)
ax2.grid(axis="y", color="#e6e5e0", lw=0.7); ax2.set_axisbelow(True)
ax2.set_title("(b) Near-duplicate prompt pairs", fontsize=9.5, pad=8)
fig.tight_layout(); save(fig, "figure15_dataset_diversity.png")

# ── Figure 16: per-stratum accuracy + System C error modes ────────────────
rows = list(csv.DictReader(open(os.path.join(HERE,"results_v2","experimental_results.csv"))))
sysrows = defaultdict(list)
for r in rows: sysrows[r["System_Configuration"]].append(r)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(5.1, 2.45),
                               gridspec_kw={"width_ratios":[1,1.25]})
strata = ["direct","indirect","injection"]
def acc(s, st):
    rs = [r for r in sysrows[s] if r["Stratum"] == st]
    return 100*sum(1 for r in rs if ok(r))/len(rs)
x, w = np.arange(3), 0.36
b1 = ax1.bar(x-w/2, [acc("System_B",s) for s in strata], w*0.94, color=BLUE,
             label="System B (centralized)")
b2 = ax1.bar(x+w/2, [acc("System_C",s) for s in strata], w*0.94, color=AQUA,
             label="System C (blockchain)")
lab(ax1, b1, "{:.1f}"); lab(ax1, b2, "{:.1f}")
ax1.set_ylim(0,118); ax1.set_yticks([0,25,50,75,100])
ax1.set_ylabel("Policy conformance (%)")
ax1.set_xticks(x, [f"{s}\n(n={len([r for r in sysrows['System_C'] if r['Stratum']==s])})"
                   for s in strata], fontsize=8.5)
ax1.grid(axis="y", color="#e6e5e0", lw=0.7); ax1.set_axisbelow(True)
ax1.legend(frameon=False, fontsize=8.5, loc="upper center",
           bbox_to_anchor=(0.5,-0.20), ncol=1)
ax1.set_title("(a) Conformance by difficulty stratum", fontsize=9.5, pad=8)

over, leak = [], []
for t in TOOLS:
    rs = [r for r in sysrows["System_C"] if r["Target_Tool"] == t and not ok(r)]
    over.append(sum(1 for r in rs if norm(r["Intended_Policy"]) == "ALLOW"))
    leak.append(sum(1 for r in rs if norm(r["Intended_Policy"]) == "DENY"))
xt = np.arange(len(TOOLS))
p1 = ax2.bar(xt, over, 0.55, color=BLUE, label="over-restriction (ALLOW$\\rightarrow$DENY)")
p2 = ax2.bar(xt, leak, 0.55, bottom=over, color=RED, label="leakage (DENY$\\rightarrow$ALLOW)")
for i,(o,l) in enumerate(zip(over,leak)):
    if o: ax2.text(i, o/2, str(o), ha="center", va="center", fontsize=8.5, color="white")
    if l: ax2.text(i, o+l/2, str(l), ha="center", va="center", fontsize=8.5, color="white")
ax2.set_ylim(0, max(np.array(over)+np.array(leak))*1.3)
ax2.set_ylabel("System C errors (of 60 per tool)")
ax2.set_xticks(xt, [t.replace("_","\n") for t in TOOLS], fontsize=8)
ax2.grid(axis="y", color="#e6e5e0", lw=0.7); ax2.set_axisbelow(True)
ax2.legend(frameon=False, fontsize=8, loc="upper center",
           bbox_to_anchor=(0.5,-0.20), ncol=1)
ax2.set_title("(b) System C error modes by tool", fontsize=9.5, pad=8)
fig.tight_layout(); save(fig, "figure16_stratum_accuracy.png")
