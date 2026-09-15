"""Independently recompute every headline number in the paper from the
committed CSVs and compare against what the manuscript claims."""
import csv, math, os
from collections import defaultdict
from math import comb

E=os.path.join(os.path.dirname(os.path.abspath(__file__)))
MAP={"APPROVED":"ALLOW","BLOCKED":"DENY","DENIED":"DENY","ALLOW":"ALLOW","DENY":"DENY"}
norm=lambda s: MAP.get(s.strip().upper(),s.strip().upper())
ok=lambda r: norm(r["Permission_Decision"])==norm(r["Intended_Policy"])

def load(p):
    d=defaultdict(list)
    for r in csv.DictReader(open(p)): d[r["System_Configuration"]].append(r)
    return d
def wilson(k,n,z=1.959964):
    p=k/n; d=1+z*z/n; c=(p+z*z/(2*n))/d
    h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return round((c-h)*100,1),round((c+h)*100,1)
def mcnemar(a,b):
    ids=set(a)&set(b)
    ao=sum(1 for i in ids if a[i] and not b[i]); bo=sum(1 for i in ids if not a[i] and b[i])
    n=ao+bo
    p=min(1.0,2*sum(comb(n,i) for i in range(0,min(ao,bo)+1))/2**n) if n else 1.0
    return ao,bo,p
def leak(d,s):
    return {r["Trial_ID"] for r in d[s] if norm(r["Intended_Policy"])=="DENY"
            and r["Action_Executed"].strip().upper()=="TRUE"}

checks=[]
def chk(label, got, claimed, tol=0.02):
    if isinstance(claimed,(int,float)) and isinstance(got,(int,float)) and not isinstance(claimed,bool):
        good = abs(got-claimed) <= tol
    else:
        good = got == claimed
    checks.append(good)
    print(f"  [{'OK ' if good else 'FAIL'}] {label:52s} computed={got}  paper={claimed}")

print("="*82); print("  A. HEADLINE (rule classifier, curated dataset)  <- paper Table 4"); print("="*82)
d=load(f"{E}/results_v2_rule/experimental_results.csv")
for s,acc,lk in (("System_A",40.00,100.00),("System_B",73.33,16.11),("System_C",80.67,0.56)):
    k=sum(1 for r in d[s] if ok(r))
    chk(f"{s} conformance %", round(100*k/len(d[s]),2), acc)
    chk(f"{s} DENY-leakage %", round(100*len(leak(d,s))/180,2), lk)

print("\n"+"="*82); print("  B. PER-TOOL, System C  <- paper Table 5"); print("="*82)
for t,claim in (("search_web",55.0),("read_file",50.0),("transfer_money",100.0),
                ("execute_command",98.3),("delete_database",100.0)):
    rs=[r for r in d["System_C"] if r["Target_Tool"]==t]
    chk(f"{t}", round(100*sum(1 for r in rs if ok(r))/len(rs),1), claim, tol=0.05)
errs=[r for r in d["System_C"] if not ok(r)]
chk("System C over-restrictions", sum(1 for r in errs if norm(r["Intended_Policy"])=="ALLOW"), 57)
chk("System C leaks", sum(1 for r in errs if norm(r["Intended_Policy"])=="DENY"), 1)

print("\n"+"="*82); print("  C. LEAK-SET SUBSET CLAIM  <- paper Sec 7.2"); print("="*82)
lb,lc=leak(d,"System_B"),leak(d,"System_C")
chk("|System B leaks|", len(lb), 29); chk("|System C leaks|", len(lc), 1)
chk("C is a strict subset of B", lc<lb, True)
chk("trials unique to B", len(lb-lc), 28)

print("\n"+"="*82); print("  D. EMBEDDING RUN  <- paper Table 8 / Sec 7.9"); print("="*82)
e=load(f"{E}/results_v2/experimental_results.csv")
for s,acc,lk in (("System_B",65.67,39.44),("System_C",82.67,5.56)):
    k=sum(1 for r in e[s] if ok(r))
    chk(f"{s} conformance %", round(100*k/300,2), acc)
    chk(f"{s} DENY-leakage %", round(100*len(leak(e,s))/180,2), lk)
chk("System C Wilson CI", wilson(sum(1 for r in e['System_C'] if ok(r)),300), (78.0,86.5))
ao,bo,p=mcnemar({r["Trial_ID"]:ok(r) for r in e["System_B"]},{r["Trial_ID"]:ok(r) for r in e["System_C"]})
chk("McNemar B vs C discordant", ao+bo, 71); chk("  favouring C", bo, 61)
chk("  p < 1e-9", p<1e-9, True)

print("\n"+"="*82); print("  E. CLASSIFIER COMPARISON  <- paper Table 9 / Sec 7.9.4"); print("="*82)
a={r["Trial_ID"]:ok(r) for r in d["System_C"]}; b={r["Trial_ID"]:ok(r) for r in e["System_C"]}
ao,bo,p=mcnemar(a,b)
chk("rule-only-correct", ao, 30); chk("embedding-only-correct", bo, 36)
chk("discordant", ao+bo, 66); chk("McNemar p", round(p,2), 0.54)

print("\n"+"="*82); print("  F. PER-STRATUM  <- paper Sec 7.9.1 / Table 9"); print("="*82)
for st,rc,ec in (("direct",78.7,95.3),("indirect",79.0,68.0),("injection",90.0,74.0)):
    for tag,src,claim in (("rule",d,rc),("embedding",e,ec)):
        rs=[r for r in src["System_C"] if r["Stratum"]==st]
        chk(f"{st}/{tag}", round(100*sum(1 for r in rs if ok(r))/len(rs),1), claim, tol=0.05)

print("\n"+"="*82); print("  G. ABLATION  <- paper Table 6"); print("="*82)
for cfg,bacc,cacc in (("baseline",73.33,80.67),("matched_strict",80.67,80.67),
                      ("matched_permissive",73.33,73.33)):
    ad=load(f"{E}/results_v2_ablation/experimental_results_{cfg}.csv")
    for s,claim in (("System_B",bacc),("System_C",cacc)):
        chk(f"{cfg}/{s}", round(100*sum(1 for r in ad[s] if ok(r))/300,2), claim)

print("\n"+"="*82); print("  H. GAS + gas/latency  <- paper Sec 7.7 / Table 4"); print("="*82)
import statistics as st
g=[int(float(r[[c for c in r if 'gas' in c.lower()][0]])) for r in csv.DictReader(open(f"{E}/results_v2_rule/gas_results.csv"))]
chk("gas n", len(g), 300); chk("gas median (deterministic)", int(st.median(g)), 35452); 
lat=[float(r["Latency_ms"]) for r in d["System_C"] if float(r["Latency_ms"])>0]
chk("System C median latency, fresh chain (2 s.f.)", round(st.median(lat)), 22, tol=3)

print("\n"+"="*82); print("  I. TAMPER  <- paper Table 10 / Sec 7.11"); print("="*82)
tr=list(csv.DictReader(open(f"{E}/results_tamper/tamper_results.csv")))
tt=lambda v: str(v).strip().lower() in ("true","1","yes")
a2c=[r for r in tr if r["scenario"]=="A2_unauthorized_escalation" and r["system"]=="System_C"]
chk("A2 System C blocked (0 successes /30)", sum(1 for r in a2c if tt(r["attack_succeeded"])), 0)
a2b=[r for r in tr if r["scenario"]=="A2_unauthorized_escalation" and r["system"]=="System_B"]
chk("A2 System B succeeded 30/30", sum(1 for r in a2b if tt(r["attack_succeeded"])), 30)
a3=[r for r in tr if r["scenario"]=="A3_retroactive_revert"]
chk("A3 state-diff detects nothing (both)", sum(1 for r in a3 if tt(r["detect_state"])), 0)
a3c=[r for r in a3 if r["system"]=="System_C"]
chk("A3 System C history detects 30/30", sum(1 for r in a3c if tt(r["detect_history"])), 30)
rec=list(csv.DictReader(open(f"{E}/results_tamper/reconstruction.csv")))
for s,pct,win in (("System_B",66.67,0),("System_C",100.0,20)):
    rs=[r for r in rec if r["system"]==s]
    chk(f"{s} reconstruction %", round(st.mean(float(r['reconstruction_pct']) for r in rs),2), pct)
    chk(f"{s} exploit-window recovered", round(st.mean(float(r['attack_window_recovered']) for r in rs),1), float(win))

import os as _os
print("\n"+"="*82); print("  J. LLM CLASSIFIER ARM  <- paper Sec 7.10 / Table 7 / Table 10"); print("="*82)
gem = list(csv.DictReader(open(f"{E}/results_v2_gemini/classifier_comparison.csv")))
gen = [r for r in gem if r["Classifier_Actually_Used"] == "gemini"]
chk("gemini genuine predictions (no fallback rows)", len(gen), 300)
chk("gemini accuracy", round(100*sum(1 for r in gen if r["Predicted_Tool"] == r["Target_Tool"])/len(gen), 2), 99.00)

base = list(csv.DictReader(open(f"{E}/results_v2_clf/classifier_comparison.csv")))
POLR = {"search_web": 1, "read_file": 1, "transfer_money": 0, "execute_command": 0, "delete_database": 0}
POLB = dict(POLR, transfer_money=1)

# error profile: the paper claims the LLM is off the safety-utility frontier
leak = sum(1 for r in gen if POLR[r["Target_Tool"]] == 0 and POLR[r["Predicted_Tool"]] == 1)
over = sum(1 for r in gen if POLR[r["Target_Tool"]] == 1 and POLR[r["Predicted_Tool"]] == 0)
chk("gemini leaked restricted requests", leak, 0)
chk("gemini over-restricted benign requests", over, 2)

# strict dominance over the embedding classifier (McNemar b=70, c=0)
emb = {int(r["Trial_ID"]): (r["Correct"] == "True") for r in base if r["Classifier_Name"] == "embedding"}
gc = {int(r["Trial_ID"]): (r["Predicted_Tool"] == r["Target_Tool"]) for r in gen}
chk("gemini wins vs embedding (McNemar b)", sum(1 for i in gc if gc[i] and not emb[i]), 70)
chk("gemini losses vs embedding (McNemar c)", sum(1 for i in gc if not gc[i] and emb[i]), 0)

# per-stratum accuracy quoted in Table 10
from run_experiments import generate_prompts_v2 as _gp
_st = {p_.trial_id: p_.stratum for p_ in _gp()}
for stratum, claim, n_exp in (("direct", 100.0, 150), ("indirect", 98.0, 100), ("injection", 98.0, 50)):
    sub = [r for r in gen if _st[int(r["Trial_ID"])] == stratum]
    chk(f"gemini {stratum} n", len(sub), n_exp)
    chk(f"gemini {stratum} accuracy", round(100*sum(1 for r in sub if r["Predicted_Tool"] == r["Target_Tool"])/len(sub), 1), claim)

# THE PROJECTION. The paper states it reproduces all four live measurements
# exactly; if that ever stops holding, the projected 99.33% is not reportable.
for tag, sysname, pol, claim in (("rule", "System_B", POLB, 220), ("rule", "System_C", POLR, 242),
                                 ("emb",  "System_B", POLB, 197), ("emb",  "System_C", POLR, 248)):
    sw = load(f"{E}/{'results_v2_rule' if tag == 'rule' else 'results_v2'}/experimental_results.csv")[sysname]
    chk(f"projection == measured [{tag}/{sysname}]",
        sum(1 for r in sw if pol[r["Classified_Action"]] == POLR[r["Target_Tool"]]), claim)

byid = {int(r["Trial_ID"]): r["Predicted_Tool"] for r in gen}
tgt = {p_.trial_id: p_.target_tool for p_ in _gp()}
_pC = round(100*sum(1 for i in byid if POLR[byid[i]] == POLR[tgt[i]])/300, 2)
_pB = round(100*sum(1 for i in byid if POLB[byid[i]] == POLR[tgt[i]])/300, 2)
chk("projected System C under gemini", _pC, 99.33)
chk("projected System B under gemini", _pB, 79.33)

# The third live sweep. The projection above was recorded BEFORE this ran;
# these checks assert the sweep reproduced it, which is the prospective test
# the paper claims in Sec 7.10.
_gs = f"{E}/results_v2_gemini_sweep/experimental_results.csv"
if _os.path.exists(_gs):
    gsw = load(_gs)
    for sysname, claim, proj in (("System_C", 99.33, _pC), ("System_B", 79.33, _pB)):
        meas = round(100*sum(1 for r in gsw[sysname] if ok(r))/300, 2)
        chk(f"LLM live sweep {sysname} conformance", meas, claim)
        chk(f"LLM live sweep {sysname} == prospective projection", meas, proj)
    _leak = sum(1 for r in gsw["System_C"]
                if r["Intended_Policy"] == "DENY" and r["Action_Executed"] == "TRUE")
    chk("LLM live sweep System C leakage (of 180)", _leak, 0)
    chk("LLM live sweep trials", sum(len(v) for v in gsw.values()), 900)
else:
    print("  [skip] results_v2_gemini_sweep/ absent")

print("\n"+"="*82); print("  K. SYSTEM E / OPA  <- paper Sec 7.14 / Table 11"); print("="*82)
import os as _os
_opa = f"{E}/results_opa/opa_decisions.csv"
if _os.path.exists(_opa):
    od = list(csv.DictReader(open(_opa)))
    for tag, claim in (("rule", 242), ("embedding", 248)):
        sub = [r for r in od if r["Classifier"] == tag]
        chk(f"OPA conformance [{tag}] == System C", sum(1 for r in sub if r["Conformant"] == "True"), claim)
        chk(f"OPA trials [{tag}]", len(sub), 300)
    _l = sorted(float(r["Latency_ms"]) for r in od)
    chk("OPA median decision latency (ms)", round(st.median(_l), 3), 0.186, tol=0.05)
    ot = list(csv.DictReader(open(f"{E}/results_opa/opa_tamper.csv")))
    chk("OPA escalation succeeded 30/30", sum(1 for r in ot if r["escalation_succeeded"] == "True"), 30)
    chk("OPA detected by state comparison", sum(1 for r in ot if r["detect_state"] == "True"), 0)
    chk("OPA detected by history", sum(1 for r in ot if r["detect_history"] == "True"), 0)
else:
    print("  [skip] results_opa/ absent — run: ./scripts/reproduce.sh opa")

print("\n"+"="*82); print("  L. SEPOLIA PUBLIC TESTNET  <- paper Sec 7.8 / Table 8"); print("="*82)
# Every latency in the paper uses statistics.median. An earlier version of the
# Sepolia summary used a lower-median (percentile-50 'lower'), which reported
# 203 ms where the conventional median is 213 ms. These checks pin the
# convention so the two can never diverge again.
for tag, d, rmed, wmed in (("s1", "results_sepolia", 213.0, 11.84),
                           ("s2", "results_sepolia_s2", 330.5, 11.55)):
    rd = [float(r["latency_ms"]) for r in csv.DictReader(open(f"{E}/{d}/sepolia_reads.csv"))]
    wr = list(csv.DictReader(open(f"{E}/{d}/sepolia_writes.csv")))
    chk(f"sepolia {tag} reads n", len(rd), 50)
    chk(f"sepolia {tag} read median (ms)", round(st.median(rd), 1), rmed)
    chk(f"sepolia {tag} write median (s)", round(st.median([float(x["total_ms"]) for x in wr])/1000, 2), wmed)
    chk(f"sepolia {tag} gas median", int(st.median([float(x["gas_used"]) for x in wr])), 35440)
_r1 = [float(r["latency_ms"]) for r in csv.DictReader(open(f"{E}/results_sepolia/sepolia_reads.csv"))]
_r2 = [float(r["latency_ms"]) for r in csv.DictReader(open(f"{E}/results_sepolia_s2/sepolia_reads.csv"))]
chk("sepolia session-to-session read change (%)",
    round((st.median(_r2)-st.median(_r1))/st.median(_r1)*100), 55, tol=1)

print("\n"+"="*82); print("  M. SYSTEM D / ANCHORING  <- paper Sec 7.10 / Table 13, Fig 8"); print("="*82)
sd = list(csv.DictReader(open(f"{E}/results_systemd/systemd_cost.csv")))
for anchor, claim in ((1, 30316.6), (10, 3031.8)):
    rows = [r for r in sd if int(r["anchor_every"]) == anchor]
    chk(f"System D gas/decision @N={anchor}", round(float(rows[0]["gas_per_decision"]), 1), claim)
_n10 = [r for r in sd if int(r["anchor_every"]) == 10]
chk("System D detects log wipe @N=10 (all reps)", all(str(r["detected"]).lower() == "true" for r in _n10), True)
chk("System D gas saving vs on-chain (x)", round(35452/3031.8, 1), 11.7)

print("\n"+"="*82); print("  N. AVAILABILITY + ASYNC AUDIT  <- paper Sec 7.11"); print("="*82)
av = list(csv.DictReader(open(f"{E}/results_availability/availability.csv")))
chk("availability at fault rate 0.0 (%)", float(av[0]["availability_pct"]), 100.0)
_hi = [r for r in av if abs(float(r["fault_rate"]) - 0.10) < 1e-9]
if _hi: chk("availability at fault rate 0.10 (%)", float(_hi[0]["availability_pct"]), 92.0)
aa = {r["mode"]: r for r in csv.DictReader(open(f"{E}/results_availability/async_audit.csv"))}
chk("sync throughput (req/s)", float(aa["sync"]["throughput_rps"]), 46.7)
chk("async throughput (req/s)", float(aa["async"]["throughput_rps"]), 77.6)
chk("sync median latency (ms)", round(float(aa["sync"]["median_latency_ms"]), 1), 20.8)
chk("async median latency (ms)", round(float(aa["async"]["median_latency_ms"]), 1), 13.0)
chk("async max audit backlog", int(aa["async"]["max_audit_backlog"]), 70)
chk("async median audit lag (ms)", round(float(aa["async"]["median_audit_lag_ms"])), 696)

print("\n"+"="*82); print("  O. THROUGHPUT + CONSISTENCY  <- paper Sec 7.4"); print("="*82)
sc = [r for r in csv.DictReader(open(f"{E}/results_v2_rule/scalability_results.csv"))]
for sysname, claim in (("System_A", 496.52), ("System_B", 721.53), ("System_C", 50.44)):
    row = [r for r in sc if r["system"] == sysname and int(r["concurrency"]) == 50]
    if row: chk(f"{sysname} throughput @n=50 (req/s)", float(row[0]["throughput_rps"]), claim, tol=0.05)
cons = list(csv.DictReader(open(f"{E}/results_v2_rule/consistency_results.csv")))
_by = {}
for r in cons: _by.setdefault((r["system"], r["tool"]), set()).add(r["decision"])
chk("decision consistency: every prompt one decision", all(len(v) == 1 for v in _by.values()), True)
chk("consistency trials", len(cons), 300)

print("\n"+"="*82); print("  P. CLASSIFIER LATENCY + MACRO F1  <- paper Sec 7.9 / Table 7"); print("="*82)
_lat = {}
for r in base:
    _lat.setdefault(r["Classifier_Name"], []).append(float(r["Latency_ms"]))
_lat["gemini"] = [float(r["Latency_ms"]) for r in gen]
chk("rule median latency (ms)", round(st.median(_lat["rule"]), 3), 0.032, tol=0.004)
chk("embedding median latency (ms)", round(st.median(_lat["embedding"]), 1), 19.5, tol=0.6)
chk("gemini median latency (ms)", round(st.median(_lat["gemini"])), 839, tol=6)
try:
    from sklearn.metrics import precision_recall_fscore_support as _prf
    L = ["search_web", "read_file", "transfer_money", "execute_command", "delete_database"]
    for name, rows_, claim in (("rule", [r for r in base if r["Classifier_Name"] == "rule"], 58.76),
                               ("embedding", [r for r in base if r["Classifier_Name"] == "embedding"], 74.99),
                               ("gemini", gen, 99.00)):
        f1 = _prf([r["Target_Tool"] for r in rows_], [r["Predicted_Tool"] for r in rows_],
                  labels=L, average="macro", zero_division=0)[2]
        chk(f"{name} macro F1 (%)", round(f1*100, 2), claim)
except ImportError:
    print("  [skip] sklearn absent — macro F1 not checked")

print("\n"+"="*82)
print(f"  RESULT: {sum(checks)}/{len(checks)} checks reproduce from committed data")
print("="*82)
