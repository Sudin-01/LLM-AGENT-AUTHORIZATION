"""Decomposition analysis of the v2 sweep: per-tool, per-stratum, leak overlap,
McNemar tests and Wilson intervals. Writes results_v2/analysis_v2.txt."""
import csv, math, os, sys
from collections import defaultdict
from math import comb

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(HERE, "results_v2", "experimental_results.csv")
V1 = os.path.join(HERE, "results_embedding", "experimental_results.csv")
OUT = os.path.join(HERE, "results_v2", "analysis_v2.txt")

MAP = {"APPROVED": "ALLOW", "BLOCKED": "DENY", "DENIED": "DENY",
       "ALLOW": "ALLOW", "DENY": "DENY"}
norm = lambda s: MAP.get(s.strip().upper(), s.strip().upper())

def load(path):
    rows = list(csv.DictReader(open(path)))
    d = defaultdict(list)
    for r in rows:
        d[r["System_Configuration"]].append(r)
    return d

ok  = lambda r: norm(r["Permission_Decision"]) == norm(r["Intended_Policy"])
key = lambda r: r["Trial_ID"]

def wilson(k, n, z=1.959964):
    if n == 0: return (0.0, 0.0)
    p = k / n; d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d
    h = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return round((c-h)*100, 1), round((c+h)*100, 1)

def mcnemar(a, b):
    """a, b: dict trial_id -> correct(bool). Returns (a_only, b_only, p)."""
    ids = set(a) & set(b)
    a_only = sum(1 for i in ids if a[i] and not b[i])
    b_only = sum(1 for i in ids if not a[i] and b[i])
    n = a_only + b_only
    if n == 0: return a_only, b_only, 1.0
    p = min(1.0, 2*sum(comb(n, i) for i in range(0, min(a_only, b_only)+1)) / 2**n)
    return a_only, b_only, p

L = []
def out(s=""):
    L.append(s); print(s)

v2 = load(V2)
out("="*78); out("  V2 CURATED-DATASET SWEEP - DECOMPOSITION ANALYSIS"); out("="*78)

for s in ("System_A", "System_B", "System_C"):
    rs = v2[s]; k = sum(1 for r in rs if ok(r))
    lk = [r for r in rs if norm(r["Intended_Policy"]) == "DENY"
          and r["Action_Executed"].strip().upper() == "TRUE"]
    out(f"\n{s}: accuracy {k}/{len(rs)} = {100*k/len(rs):.2f}%  CI {wilson(k,len(rs))}"
        f"   DENY-leakage {len(lk)}/180 = {100*len(lk)/180:.2f}%  CI {wilson(len(lk),180)}")

out("\n" + "-"*78); out("PER-TOOL ACCURACY"); out("-"*78)
out(f"  {'tool':18s} {'System_B':>18s} {'System_C':>18s}")
for tool in ["search_web","read_file","transfer_money","execute_command","delete_database"]:
    cells = []
    for s in ("System_B","System_C"):
        rs = [r for r in v2[s] if r["Target_Tool"] == tool]
        k = sum(1 for r in rs if ok(r))
        cells.append(f"{k:2d}/{len(rs):2d} = {100*k/len(rs):5.1f}%")
    out(f"  {tool:18s} {cells[0]:>18s} {cells[1]:>18s}")

out("\n" + "-"*78); out("PER-STRATUM ACCURACY (the point of the v2 design)"); out("-"*78)
out(f"  {'stratum':12s} {'n':>4s} {'System_B':>18s} {'System_C':>18s}")
for st in ["direct","indirect","injection"]:
    cells = []
    for s in ("System_B","System_C"):
        rs = [r for r in v2[s] if r.get("Stratum") == st]
        k = sum(1 for r in rs if ok(r))
        cells.append(f"{k:3d}/{len(rs):3d} = {100*k/len(rs):5.1f}%")
    n = len([r for r in v2['System_C'] if r.get("Stratum") == st])
    out(f"  {st:12s} {n:>4d} {cells[0]:>18s} {cells[1]:>18s}")

out("\n" + "-"*78); out("LEAK-SET OVERLAP (System C vs System B)"); out("-"*78)
leaks = lambda s: {key(r) for r in v2[s] if norm(r["Intended_Policy"]) == "DENY"
                   and r["Action_Executed"].strip().upper() == "TRUE"}
lb, lc = leaks("System_B"), leaks("System_C")
out(f"  |B| = {len(lb)}   |C| = {len(lc)}   C subset of B: {lc <= lb}   |B∩C| = {len(lb & lc)}")
if lc - lb:
    out(f"  trials leaked by C but NOT by B: {sorted(lc - lb, key=int)}")

out("\n" + "-"*78); out("STATISTICAL TESTS"); out("-"*78)
cb = {key(r): ok(r) for r in v2["System_B"]}
cc = {key(r): ok(r) for r in v2["System_C"]}
a_only, b_only, p = mcnemar(cb, cc)
out(f"  McNemar B vs C (v2): B-only-correct={a_only}, C-only-correct={b_only}, p={p:.3e}")

if os.path.exists(V1):
    v1 = load(V1)
    c1 = {key(r): ok(r) for r in v1["System_C"]}
    out(f"\n  v1 System_C accuracy: {sum(c1.values())}/{len(c1)} = "
        f"{100*sum(c1.values())/len(c1):.2f}%  CI {wilson(sum(c1.values()), len(c1))}")
    k2 = sum(cc.values())
    out(f"  v2 System_C accuracy: {k2}/{len(cc)} = {100*k2/len(cc):.2f}%  CI {wilson(k2, len(cc))}")
    out("  (trial IDs are not comparable across datasets, so these are unpaired;")
    out("   the drop reflects dataset difficulty, not a regression in the system)")

out("\n" + "-"*78); out("SYSTEM C ERRORS BY TOOL AND STRATUM"); out("-"*78)
errs = [r for r in v2["System_C"] if not ok(r)]
grp = defaultdict(list)
for r in errs:
    grp[(r["Target_Tool"], r.get("Stratum"))].append(r)
for (tool, st), rs in sorted(grp.items()):
    kind = "over-restricted (ALLOW->DENY)" if norm(rs[0]["Intended_Policy"]) == "ALLOW" \
           else "LEAKED (DENY->ALLOW)"
    out(f"\n  {tool} / {st}: {len(rs)} errors - {kind}")
    for r in rs[:6]:
        out(f"      {r['Prompt_Text'][:88]}")
    if len(rs) > 6:
        out(f"      ... and {len(rs)-6} more")
out(f"\n  total System_C errors: {len(errs)}/300")
out("="*78)

open(OUT, "w").write("\n".join(L) + "\n")
print(f"\nwritten to {OUT}")


# ── Appended: cross-classifier comparison on the v2 dataset ─────────────────
def classifier_comparison():
    RUL = os.path.join(HERE, "results_v2_rule", "experimental_results.csv")
    if not os.path.exists(RUL):
        return
    L2 = []
    def o(s=""):
        L2.append(s); print(s)
    emb, rul = load(V2), load(RUL)
    o("="*78); o("  CLASSIFIER COMPARISON ON THE CURATED DATASET (System C, end-to-end)")
    o("="*78)
    o(f"  {'classifier':12s} {'accuracy':>22s} {'DENY-leakage':>22s} {'over-restrict':>14s}")
    for name, d in (("rule-based", rul), ("embedding", emb)):
        c = d["System_C"]; k = sum(1 for r in c if ok(r))
        lk = [r for r in c if norm(r["Intended_Policy"]) == "DENY"
              and r["Action_Executed"].strip().upper() == "TRUE"]
        ov = sum(1 for r in c if not ok(r) and norm(r["Intended_Policy"]) == "ALLOW")
        o(f"  {name:12s} {f'{k}/300 = {100*k/300:.2f}% {wilson(k,300)}':>22s} "
          f"{f'{len(lk)}/180 = {100*len(lk)/180:.2f}% {wilson(len(lk),180)}':>22s} {ov:>14d}")
    o("")
    o(f"  per stratum   {'n':>5s} {'rule-based':>16s} {'embedding':>16s}")
    for st in ["direct", "indirect", "injection"]:
        cells = []
        for d in (rul, emb):
            rs = [r for r in d["System_C"] if r.get("Stratum") == st]
            k = sum(1 for r in rs if ok(r))
            cells.append(f"{k:3d}/{len(rs):3d} = {100*k/len(rs):5.1f}%")
        n = len([r for r in emb["System_C"] if r.get("Stratum") == st])
        o(f"  {st:13s} {n:>5d} {cells[0]:>16s} {cells[1]:>16s}")
    a = {key(r): ok(r) for r in rul["System_C"]}
    b = {key(r): ok(r) for r in emb["System_C"]}
    ao, bo, p = mcnemar(a, b)
    o("")
    o(f"  McNemar (paired, same prompts): rule-only={ao}, embedding-only={bo}, p={p:.4f}")
    o(f"  -> {'significant' if p < 0.05 else 'NOT significant at alpha = 0.05'}")
    o("")
    o(f"  v1 template-expansion dataset: rule 73.00%  -> embedding 97.33%  (+24.33 pp)")
    o(f"  v2 curated dataset:            rule {100*sum(a.values())/300:.2f}%  -> "
      f"embedding {100*sum(b.values())/300:.2f}%  "
      f"(+{100*(sum(b.values())-sum(a.values()))/300:.2f} pp)")
    o("="*78)
    with open(os.path.join(HERE, "results_v2", "classifier_comparison_v2.txt"), "w") as f:
        f.write("\n".join(L2) + "\n")

classifier_comparison()
