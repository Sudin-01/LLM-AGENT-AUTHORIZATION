"""
generate_architecture_figure.py — Figure 1, drawn to be legible at print size.

The previous version of this figure was a tall, sparse diagram scaled down to
about 3 inches in the ACM single-column format, which put its box labels under
6pt and made the rotated return-path label unreadable. It also carried two
typos. This regenerates it at the full text width of the acmsmall class
(5.48 in) with a minimum type size of 8pt, laid out horizontally so it occupies
roughly a third of the vertical space of the original.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

TEXTWIDTH_IN = 5.48          # acmsmall \textwidth
FIG_H_IN     = 2.55
BASE_FONT    = 8.0           # never smaller than this anywhere in the figure

fig, ax = plt.subplots(figsize=(TEXTWIDTH_IN, FIG_H_IN), dpi=400)
ax.set_xlim(0, 100); ax.set_ylim(0, 48); ax.axis("off")

def box(x, y, w, h, lines, bold_first=False, fs=BASE_FONT):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                 boxstyle="round,pad=0.6,rounding_size=1.2",
                 linewidth=0.8, edgecolor="black", facecolor="white"))
    n = len(lines)
    for i, ln in enumerate(lines):
        yy = y + h/2 + (n-1)*1.9/2 - i*1.9
        ax.text(x + w/2, yy, ln, ha="center", va="center", fontsize=fs,
                fontweight="bold" if (bold_first and i == 0) else "normal")

def arrow(x1, y1, x2, y2, style="-|>", rad=0.0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                 mutation_scale=8, linewidth=0.8, color="black",
                 connectionstyle=f"arc3,rad={rad}"))

# ── (a) the enforcement pipeline, laid out horizontally ─────────────────────
ax.text(2, 45.0, "(a) Five-layer enforcement pipeline", fontsize=8.5,
        fontweight="bold", ha="left", va="center")

stages = [["User", "Interface"], ["AI", "Agent"], ["Policy", "Engine"],
          ["Smart", "Contract"], ["Action", "Executor"], ["Audit", "Log"]]
W, H, GAP, X0 = 13.6, 8.4, 2.9, 2.0
y0 = 31.0
xs = []
for i, s in enumerate(stages):
    x = X0 + i * (W + GAP)
    xs.append(x)
    box(x, y0, W, H, s)
    if i:
        arrow(x - GAP + 0.4, y0 + H/2, x - 0.4, y0 + H/2)

# return path: audit log back to the interface
xr0 = xs[-1] + W/2
xr1 = xs[0] + W/2
ax.plot([xr0, xr0], [y0 - 0.6, y0 - 5.2], lw=0.8, color="black")
ax.plot([xr0, xr1], [y0 - 5.2, y0 - 5.2], lw=0.8, color="black")
arrow(xr1, y0 - 5.2, xr1, y0 - 1.0)
ax.text((xr0 + xr1)/2, y0 - 6.6, "JSON response", fontsize=BASE_FONT,
        ha="center", va="top")

# ── (b) the three enforcement backends compared ─────────────────────────────
ax.text(2, 17.0, "(b) Enforcement configurations compared", fontsize=8.5,
        fontweight="bold", ha="left", va="center")

systems = [("A — Baseline", "no policy check"),
           ("B — Centralized", "in-process dictionary"),
           ("C — Blockchain", "smart contract on EVM")]
BW, BH = 29.5, 9.2
for i, (t, sub) in enumerate(systems):
    x = 2.0 + i * (BW + 4.0)
    box(x, 3.6, BW, BH, [t, sub], bold_first=True)

fig.tight_layout(pad=0.15)
out = "../paper_acm/pics/SystemArchitectureofBlockGuard.png"
fig.savefig(out, bbox_inches="tight", pad_inches=0.02)
print(f"wrote {out}")
print(f"minimum type size in figure: {BASE_FONT}pt at {TEXTWIDTH_IN}in width")
