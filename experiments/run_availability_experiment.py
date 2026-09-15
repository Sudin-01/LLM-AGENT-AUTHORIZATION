"""
The availability cost of failing closed, and the effect of moving
the audit write off the enforcement path.

Fail-closed. The architecture specifies that any blockchain connection failure
defaults to DENY.
That is a safety property with an availability price that nothing in the paper
measured: an adversary who can degrade the RPC endpoint halts the agent. Here
we inject read faults at a controlled rate and measure how much legitimate work
still gets done.

Asynchronous audit. The audit write is synchronous on the enforcement path, which is what
bounds throughput. With BLOCKGUARD_ASYNC_AUDIT=1 the decision returns as soon
as the permission read completes and the record is written by a background
worker. That trades a safety window -- decisions executed but not yet recorded
-- for throughput, and both sides are measured here.

Usage:  python3 experiments/run_availability_experiment.py
"""
import csv
import os
import statistics as st
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "backend"))
OUT = os.path.join(HERE, "results_availability")
os.makedirs(OUT, exist_ok=True)

FAULT_RATES = [0.0, 0.01, 0.05, 0.10, 0.25]
N_REQUESTS = 200
# public Hardhat/Ganache development key; holds no value on any real network
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
AGENT = "agent_c"
ALLOWED_ACTION = "search_web"        # legitimate work: intended ALLOW


def fresh_engine(**env):
    for k, v in env.items():
        os.environ[k] = str(v)
    for m in [m for m in list(sys.modules) if m.startswith("policy_engine")]:
        del sys.modules[m]
    import importlib, json
    pe = importlib.import_module("policy_engine")
    cfg = json.load(open(os.path.join(HERE, "..", "backend", "config.json")))["ganache"]
    eng = pe.PolicyEngine(mode=pe.PolicyMode.BLOCKCHAIN,
                          contract_address=cfg["contractAddress"],
                          deployer_private_key=DEPLOYER_KEY)
    assert eng._blockchain_ready, (
        "engine fell back to the centralized path; the blockchain arm would not "
        "be exercised and the measurement would be meaningless")
    return eng


def measure_availability():
    rows = []
    print("Availability of legitimate actions against injected RPC fault rate")
    print(f"  {'fault rate':>11s} {'served':>8s} {'availability':>13s} "
          f"{'denied by fault':>16s} {'median ms':>10s}")
    for f in FAULT_RATES:
        eng = fresh_engine(BLOCKGUARD_FAULT_RATE=f, BLOCKGUARD_ASYNC_AUDIT=0)
        served = 0
        lat = []
        for _ in range(N_REQUESTS):
            t0 = time.perf_counter()
            d = eng.check_permission(AGENT, ALLOWED_ACTION, "availability probe")
            lat.append((time.perf_counter() - t0) * 1000)
            if d.permitted:
                served += 1
        avail = 100 * served / N_REQUESTS
        rows.append(dict(fault_rate=f, requests=N_REQUESTS, served=served,
                         availability_pct=round(avail, 2),
                         denied_by_fault=N_REQUESTS - served,
                         median_latency_ms=round(st.median(lat), 2)))
        print(f"  {f:>11.0%} {served:>8d} {avail:>12.2f}% "
              f"{N_REQUESTS-served:>16d} {st.median(lat):>10.2f}")
    with open(os.path.join(OUT, "availability.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader()
        w.writerows(rows)
    return rows


def measure_async():
    print("\nD3 — synchronous versus asynchronous audit write")
    print(f"  {'mode':>12s} {'throughput':>12s} {'median ms':>10s} "
          f"{'p95 ms':>8s} {'max backlog':>12s} {'audit lag ms':>13s}")
    rows = []
    for async_mode in (0, 1):
        eng = fresh_engine(BLOCKGUARD_ASYNC_AUDIT=async_mode, BLOCKGUARD_FAULT_RATE=0)
        lat, backlog_max = [], 0
        t_start = time.perf_counter()
        for _ in range(N_REQUESTS):
            t0 = time.perf_counter()
            eng.check_permission(AGENT, ALLOWED_ACTION, "throughput probe")
            lat.append((time.perf_counter() - t0) * 1000)
            backlog_max = max(backlog_max, eng.audit_backlog())
        wall = time.perf_counter() - t_start
        thr = N_REQUESTS / wall
        # let the queue drain so the lag distribution is complete
        if async_mode:
            eng._audit_q.join()
        lag = st.median(eng.audit_lag_ms) if eng.audit_lag_ms else 0.0
        sl = sorted(lat)
        rows.append(dict(mode="async" if async_mode else "sync",
                         throughput_rps=round(thr, 1),
                         median_latency_ms=round(st.median(lat), 2),
                         p95_latency_ms=round(sl[int(.95*len(sl))-1], 2),
                         max_audit_backlog=backlog_max,
                         median_audit_lag_ms=round(lag, 1)))
        print(f"  {rows[-1]['mode']:>12s} {thr:>10.1f}/s {st.median(lat):>10.2f} "
              f"{sl[int(.95*len(sl))-1]:>8.2f} {backlog_max:>12d} {lag:>13.1f}")
    with open(os.path.join(OUT, "async_audit.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader()
        w.writerows(rows)
    return rows


if __name__ == "__main__":
    a = measure_availability()
    d = measure_async()
    L = ["=" * 78, "  AVAILABILITY UNDER FAULT AND ASYNCHRONOUS AUDIT",
         f"  Generated: {datetime.now(timezone.utc).isoformat()}", "=" * 78, "",
         "Fail-closed availability", ""]
    for r in a:
        L.append(f"  fault {r['fault_rate']:>5.0%}   availability {r['availability_pct']:>6.2f}%   "
                 f"legitimate actions denied {r['denied_by_fault']:>3d}/{r['requests']}")
    L += ["", "Audit write placement", ""]
    for r in d:
        L.append(f"  {r['mode']:>5s}   {r['throughput_rps']:>7.1f} req/s   "
                 f"median {r['median_latency_ms']:>6.2f} ms   p95 {r['p95_latency_ms']:>6.2f} ms   "
                 f"max backlog {r['max_audit_backlog']:>3d}   audit lag {r['median_audit_lag_ms']:.0f} ms")
    if len(d) == 2:
        L.append(f"\n  speed-up from moving the audit write off the enforcement path: "
                 f"{d[1]['throughput_rps']/d[0]['throughput_rps']:.1f}x")
    L.append("=" * 78)
    txt = "\n".join(L)
    open(os.path.join(OUT, "availability_summary.txt"), "w").write(txt + "\n")
    print("\n" + txt)
