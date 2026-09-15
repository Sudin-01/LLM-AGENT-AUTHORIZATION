"""Figure: cost and detection as a function of anchor granularity (System D)."""
import csv, os, statistics as st
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE=os.path.dirname(os.path.abspath(__file__))
SRC=os.path.join(HERE,"results_systemd")
OUTS=[os.path.join(HERE,"..","paper","figures"),os.path.join(HERE,"..","paper_fcds","pics")]
BLUE,AQUA,RED,INK,INK2="#2a78d6","#1baf7a","#e34948","#0b0b0b","#52514e"
plt.rcParams.update({"font.family":"serif","font.serif":["Times New Roman","Times","DejaVu Serif"],
 "font.size":7,"axes.edgecolor":INK2,"axes.labelcolor":INK,"text.color":INK,
 "xtick.color":INK2,"ytick.color":INK2,"axes.spines.top":False,"axes.spines.right":False,
 "figure.facecolor":"white","axes.facecolor":"white"})

cost=list(csv.DictReader(open(os.path.join(SRC,"systemd_cost.csv"))))
rows=list(csv.DictReader(open(os.path.join(SRC,"systemd_results.csv"))))
tt=lambda v:str(v).strip().lower() in ("true","1","yes")

order=["D (anchor every 1)","D (anchor every 10)","D (anchor every 100)","D (signed chain, no anchor)"]
short=["N=1","N=10","N=100","no anchor"]
gas=[st.mean(float(c["gas_per_decision"]) for c in cost if c["system"]==s) for s in order]
det=[100*sum(1 for c in cost if c["system"]==s and tt(c["detected"]))/
     max(1,len([c for c in cost if c["system"]==s])) for s in order]
gas.append(35452.0); short.append("System C\n(on-chain policy)"); det.append(100.0)

fig,(ax1,ax2)=plt.subplots(1,2,figsize=(5.1,2.5))
x=np.arange(len(short))
cols=[AQUA]*4+[BLUE]
b=ax1.bar(x,gas,0.6,color=cols)
for r in b:
    ax1.text(r.get_x()+r.get_width()/2,r.get_height()+900,f"{int(r.get_height()):,}",
             ha="center",va="bottom",fontsize=6.2,color=INK)
ax1.set_ylim(0,42000); ax1.set_ylabel("Gas per decision")
ax1.set_xticks(x,short,fontsize=6.2)
ax1.grid(axis="y",color="#e6e5e0",lw=0.7); ax1.set_axisbelow(True)
ax1.set_title("(a) On-chain cost",fontsize=8,pad=6)

b2=ax2.bar(x,det,0.6,color=[AQUA if d==100 else RED for d in det[:4]]+[BLUE])
for r,d in zip(b2,det):
    ax2.text(r.get_x()+r.get_width()/2,r.get_height()+2.5,f"{d:.0f}",
             ha="center",va="bottom",fontsize=6.2,color=INK)
ax2.set_ylim(0,118); ax2.set_yticks([0,50,100])
ax2.set_ylabel("Log tampering detected (%)")
ax2.set_xticks(x,short,fontsize=6.2)
ax2.grid(axis="y",color="#e6e5e0",lw=0.7); ax2.set_axisbelow(True)
ax2.set_title("(b) Detection of a privileged log rewrite",fontsize=8,pad=6)
fig.tight_layout()
for d in OUTS:
    if os.path.isdir(d):
        p=os.path.join(d,"figure17_systemd_anchoring.png")
        fig.savefig(p,dpi=300,bbox_inches="tight"); print("wrote",os.path.abspath(p))
plt.close(fig)
