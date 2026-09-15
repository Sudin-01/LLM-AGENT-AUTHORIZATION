"""Regenerate every results figure from the v2 curated-dataset runs.

Primary configuration: rule-based classifier on the curated dataset
(experiments/results_v2_rule). Offline classifier metrics come from
experiments/results_v2_clf.
"""
import csv, os, re, math
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RULE = os.path.join(HERE, "results_v2_rule")
EMB  = os.path.join(HERE, "results_v2")
ABL  = os.path.join(HERE, "results_v2_ablation")
CLF  = os.path.join(HERE, "results_v2_clf")
OUTS = [os.path.join(HERE, "..", "paper", "figures"),
        os.path.join(HERE, "..", "paper_fcds", "pics")]

BLUE, AQUA, ORANGE, RED, INK, INK2 = "#2a78d6", "#1baf7a", "#eda100", "#e34948", "#0b0b0b", "#52514e"
plt.rcParams.update({
    "font.family":"serif","font.serif":["Times New Roman","Times","DejaVu Serif"],
    "font.size":8,"axes.edgecolor":INK2,"axes.labelcolor":INK,"text.color":INK,
    "xtick.color":INK2,"ytick.color":INK2,"axes.spines.top":False,
    "axes.spines.right":False,"figure.facecolor":"white","axes.facecolor":"white"})

TOOLS = ["search_web","read_file","transfer_money","execute_command","delete_database"]
SYS = ["System_A","System_B","System_C"]
SYSLAB = {"System_A":"Sys A - Baseline","System_B":"Sys B - Centralised","System_C":"Sys C - Blockchain"}
MAP = {"APPROVED":"ALLOW","BLOCKED":"DENY","DENIED":"DENY","ALLOW":"ALLOW","DENY":"DENY"}
norm = lambda s: MAP.get(s.strip().upper(), s.strip().upper())
ok = lambda r: norm(r["Permission_Decision"]) == norm(r["Intended_Policy"])

def save(fig, name):
    for d in OUTS:
        if os.path.isdir(d):
            fig.savefig(os.path.join(d, name), dpi=300, bbox_inches="tight")
    print("  wrote", name); plt.close(fig)

def load(path):
    d = defaultdict(list)
    for r in csv.DictReader(open(path)): d[r["System_Configuration"]].append(r)
    return d

def lab(ax, bars, fmt="{:.1f}", dy=1.5, fs=8.5):
    for b in bars:
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+dy, fmt.format(b.get_height()),
                ha="center", va="bottom", fontsize=fs, color=INK)

main = load(os.path.join(RULE, "experimental_results.csv"))
leaks = lambda s: {r["Trial_ID"] for r in main[s]
                   if norm(r["Intended_Policy"])=="DENY" and r["Action_Executed"].strip().upper()=="TRUE"}

# ── Fig 1: headline metrics ────────────────────────────────────────────────
acc = [100*sum(1 for r in main[s] if ok(r))/len(main[s]) for s in SYS]
lkg = [100*len(leaks(s))/180 for s in SYS]
fig, ax = plt.subplots(figsize=(6.2,3.2)); x,w = np.arange(3), 0.36
b1 = ax.bar(x-w/2, acc, w*0.94, color=BLUE, label="Policy conformance")
b2 = ax.bar(x+w/2, lkg, w*0.94, color=RED,  label="DENY-leakage")
lab(ax,b1); lab(ax,b2)
ax.set_ylim(0,120); ax.set_yticks([0,25,50,75,100]); ax.set_ylabel("Percentage (%)")
ax.set_xticks(x,[SYSLAB[s] for s in SYS], fontsize=9)
ax.grid(axis="y",color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
ax.legend(frameon=False,fontsize=8.5,loc="upper center",bbox_to_anchor=(0.5,-0.14),ncol=2)
fig.tight_layout(); save(fig,"figure1_headline_metrics.png")

# ── Fig 2: leak-set Venn ───────────────────────────────────────────────────
lb, lc = leaks("System_B"), leaks("System_C")
fig, ax = plt.subplots(figsize=(5.4,3.4))
for cx,col in ((-0.42,ORANGE),(0.42,AQUA)):
    ax.add_patch(plt.Circle((cx,0),0.85,color=col,alpha=0.32,ec=col,lw=1.4))
ax.text(-0.95,0.98,"System B",ha="center",fontsize=10,color="#b06f00",fontweight="bold")
ax.text( 0.95,0.98,"System C",ha="center",fontsize=10,color="#0f7a54",fontweight="bold")
ax.text(-0.72,0,str(len(lb-lc)),ha="center",va="center",fontsize=17,color="#b06f00",fontweight="bold")
ax.text( 0.00,0,str(len(lb&lc)),ha="center",va="center",fontsize=17,color=INK,fontweight="bold")
ax.text( 0.72,0,str(len(lc-lb)),ha="center",va="center",fontsize=17,color="#0f7a54",fontweight="bold")
ax.set_xlim(-1.6,1.6); ax.set_ylim(-1.15,1.3); ax.axis("off")
ax.set_title("Leaked trials: System C is a strict subset of System B", fontsize=9.5)
fig.tight_layout(); save(fig,"figure2_leak_overlap_venn.png")

# ── Fig 3: per-tool accuracy heatmap ───────────────────────────────────────
M = np.array([[100*sum(1 for r in main[s] if r["Target_Tool"]==t and ok(r))/
               max(1,len([r for r in main[s] if r["Target_Tool"]==t])) for t in TOOLS] for s in SYS])
from matplotlib.colors import LinearSegmentedColormap
ramp = LinearSegmentedColormap.from_list("s",["#fcfcfb","#cde2fb","#86b6ef","#3987e5","#1c5cab","#0d366b"])
fig, ax = plt.subplots(figsize=(6.6,2.9))
im = ax.imshow(M, cmap=ramp, vmin=0, vmax=100, aspect="auto")
for i in range(3):
    for j in range(5):
        ax.text(j,i,f"{M[i,j]:.0f}%",ha="center",va="center",fontsize=9,
                color="white" if M[i,j]>55 else INK)
ax.set_xticks(range(5),[t.replace("_","\n") for t in TOOLS],fontsize=8.5)
ax.set_yticks(range(3),[SYSLAB[s] for s in SYS],fontsize=8.5)
ax.spines[:].set_visible(False); ax.tick_params(length=0)
fig.colorbar(im,ax=ax,fraction=0.03,pad=0.02).set_label("Conformance (%)",fontsize=8.5)
fig.tight_layout(); save(fig,"figure3_per_tool_accuracy_heatmap.png")

# ── Fig 5: latency violin ──────────────────────────────────────────────────
lat = {s:[float(r["Latency_ms"]) for r in main[s] if float(r["Latency_ms"])>0] for s in ("System_B","System_C")}
fig, ax = plt.subplots(figsize=(5.1,2.7))
parts = ax.violinplot([lat["System_B"],lat["System_C"]],showmedians=True,widths=0.7)
for pc,c in zip(parts["bodies"],[ORANGE,AQUA]):
    pc.set_facecolor(c); pc.set_alpha(0.65); pc.set_edgecolor(c)
for k in ("cbars","cmins","cmaxes","cmedians"):
    if k in parts: parts[k].set_color(INK2); parts[k].set_linewidth(1.1)
ax.set_yscale("log"); ax.set_ylabel("Enforcement latency (ms, log scale)")
ax.set_xticks([1,2],["Sys B - Centralised","Sys C - Blockchain"],fontsize=9)
for i,s in enumerate(("System_B","System_C"),start=1):
    ax.text(i+0.30, np.median(lat[s]), f"median {np.median(lat[s]):.2f} ms",
            fontsize=8.5, color=INK, va="center")
ax.grid(axis="y",color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
fig.tight_layout(); save(fig,"figure5_latency_violin.png")

# ── Fig 6: consistency ─────────────────────────────────────────────────────
cons_p = os.path.join(RULE,"consistency_results.csv")
if os.path.exists(cons_p):
    rows = list(csv.DictReader(open(cons_p)))
    vals = []
    for s_ in SYS:
        groups = defaultdict(list)
        for r in rows:
            if r["system"] == s_:
                groups[(r["tool"], r["prompt"])].append(r["decision"])
        # fraction of repeats agreeing with the modal decision, averaged over prompts
        fr = [max(v.count(d) for d in set(v))/len(v) for v in groups.values()] or [1.0]
        vals.append(100*sum(fr)/len(fr))
    fig, ax = plt.subplots(figsize=(5.6,3.0))
    bb = ax.bar(np.arange(3), vals, 0.5, color=[BLUE,ORANGE,AQUA]); lab(ax,bb)
    ax.set_ylim(0,118); ax.set_yticks([0,25,50,75,100]); ax.set_ylabel("Decision consistency (%)")
    ax.set_xticks(range(3),[SYSLAB[s_] for s_ in SYS],fontsize=9)
    ax.grid(axis="y",color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
    fig.tight_layout(); save(fig,"figure6_consistency.png")

# ── Fig 7 / 8: scalability ─────────────────────────────────────────────────
sc_p = os.path.join(RULE,"scalability_results.csv")
if os.path.exists(sc_p):
    rows = list(csv.DictReader(open(sc_p)))
    for col, fname, ylab, logy in (("throughput_rps","figure7_scalability_throughput.png","Throughput (req/s)",False),
                                   ("p95_latency_ms","figure8_scalability_p95.png","p95 latency (ms, log scale)",True)):
        fig, ax = plt.subplots(figsize=(5.1,2.7))
        for s_, c in zip(SYS,[BLUE,ORANGE,AQUA]):
            rs = sorted([r for r in rows if r["system"]==s_], key=lambda r: float(r["concurrency"]))
            if rs:
                ax.plot([float(r["concurrency"]) for r in rs],[float(r[col]) for r in rs],
                        "o-",color=c,lw=1.8,ms=5,label=SYSLAB[s_])
        if logy: ax.set_yscale("log")
        ax.set_xlabel("Concurrent agents"); ax.set_ylabel(ylab)
        ax.grid(color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
        ax.legend(frameon=False,fontsize=8.5)
        fig.tight_layout(); save(fig,fname)

# ── Fig 9: gas distribution ────────────────────────────────────────────────
gas_p=os.path.join(RULE,"gas_results.csv")
if os.path.exists(gas_p):
    rows=list(csv.DictReader(open(gas_p)))
    gcol=next(c for c in rows[0] if "gas" in c.lower())
    g=[int(float(r[gcol])) for r in rows if r[gcol]]
    fig, ax = plt.subplots(figsize=(5.1,2.7))
    ax.hist(g,bins=25,color=AQUA,edgecolor="white",lw=0.8)
    ax.axvline(np.median(g),color=INK,lw=1.1,ls="--")
    ax.text(np.median(g)-260,ax.get_ylim()[1]*0.94,f"median {int(np.median(g)):,}",
            fontsize=8.5,color=INK,ha="right")
    ax.set_xlabel("Gas used per logDecision transaction"); ax.set_ylabel(f"Count (n={len(g)})")
    ax.grid(axis="y",color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
    fig.tight_layout(); save(fig,"figure9_gas_distribution.png")

# ── Fig ablation ───────────────────────────────────────────────────────────
cfgs=[("baseline","Baseline"),("matched_strict","Matched-strict"),("matched_permissive","Matched-permissive")]
bv,cv=[],[]
for key,_ in cfgs:
    p=os.path.join(ABL,f"experimental_results_{key}.csv")
    if not os.path.exists(p): bv,cv=[],[]; break
    d=load(p)
    lk=lambda s:100*len({r["Trial_ID"] for r in d[s] if norm(r["Intended_Policy"])=="DENY"
                         and r["Action_Executed"].strip().upper()=="TRUE"})/180
    bv.append(lk("System_B")); cv.append(lk("System_C"))
if bv:
    fig, ax = plt.subplots(figsize=(6.2,3.2)); x=np.arange(3)
    r1=ax.bar(x-w/2,bv,w*0.94,color=ORANGE,label="System B (centralized)")
    r2=ax.bar(x+w/2,cv,w*0.94,color=AQUA,label="System C (blockchain)")
    lab(ax,r1,dy=0.5); lab(ax,r2,dy=0.5)
    ax.set_ylabel("DENY-leakage rate (%)"); ax.set_ylim(0,max(bv+cv)*1.35+1)
    ax.set_xticks(x,[l for _,l in cfgs],fontsize=9)
    ax.grid(axis="y",color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
    ax.legend(frameon=False,fontsize=8.5,loc="upper center",bbox_to_anchor=(0.5,-0.14),ncol=2)
    fig.tight_layout(); save(fig,"figure_ablation.png")

# ── Fig 10 / 11: offline classifier metrics ────────────────────────────────
rep=os.path.join(CLF,"classifier_metrics_report.txt")
if os.path.exists(rep):
    txt=open(rep).read()
    def metrics(name):
        m=re.search(rf"── {name} ─+\n(.*?)(?=\n── |\Z)",txt,re.S)
        if not m: return None
        b=m.group(1)
        g=lambda k: float(re.search(rf"{k}:\s+([\d.]+)%",b).group(1))
        return [g("Accuracy"),g("Macro Precision"),g("Macro Recall"),g("Macro F1")]
    mr,me=metrics("rule"),metrics("embedding")
    if mr and me:
        names=["Accuracy","Macro P","Macro R","Macro F1"]
        fig, ax = plt.subplots(figsize=(5.6,3.1)); x=np.arange(4)
        r1=ax.bar(x-w/2,mr,w*0.94,color=BLUE,label="Rule-based (fail-closed)")
        r2=ax.bar(x+w/2,me,w*0.94,color=AQUA,label="Sentence-embedding")
        lab(ax,r1); lab(ax,r2)
        ax.set_ylim(0,112); ax.set_yticks([0,25,50,75,100]); ax.set_ylabel("Score (%)")
        ax.set_xticks(x,names)
        ax.grid(axis="y",color="#e6e5e0",lw=0.7); ax.set_axisbelow(True)
        ax.legend(frameon=False,fontsize=8.5,loc="upper center",bbox_to_anchor=(0.5,-0.14),ncol=2)
        fig.tight_layout(); save(fig,"figure10_classifier_comparison.png")
    m=re.search(r"── embedding ─+.*?Confusion matrix.*?\n(.*?)(?=\n──|\Z)",txt,re.S)
    if m:
        cm=[]
        for line in m.group(1).splitlines():
            nums=re.findall(r"\b\d+\b",line)
            if len(nums)==5: cm.append([int(v) for v in nums])
        if len(cm)==5:
            cm=np.array(cm)
            labels=[t.replace("_","\n") for t in TOOLS]
            fig, ax = plt.subplots(figsize=(3.5,3.1))
            ax.imshow(cm,cmap=ramp,vmin=0,vmax=60)
            for i in range(5):
                for j in range(5):
                    v=cm[i,j]
                    ax.text(j,i,str(v),ha="center",va="center",fontsize=9,
                            color="white" if v>30 else (INK if v else "#b5b4ac"))
            ax.set_xticks(range(5),labels,fontsize=8); ax.set_yticks(range(5),labels,fontsize=8)
            ax.set_xlabel("Predicted action"); ax.set_ylabel("Actual action")
            ax.spines[:].set_visible(False); ax.tick_params(length=0)
            fig.tight_layout(); save(fig,"figure11_confusion_matrix_embedding.png")
print("done")
