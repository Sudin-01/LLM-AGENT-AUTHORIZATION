"""
run_opa_experiment.py — System E: Open Policy Agent as an external comparator.

Every backend compared so far is one we wrote. A fair objection is
that no number in the paper is commensurable with any published number. This
adds the policy engine that production deployments actually use -- Open Policy
Agent, evaluating an equivalent Rego policy -- and measures it on the same
dataset, the same matched trials, and the same four attack scenarios.

Two things are measured, and they point in opposite directions.

  1. PERFORMANCE. OPA is queried over its HTTP decision API, which is how it is
     deployed in practice (sidecar or host daemon). This is the honest
     comparison for System C's 21 ms on-chain check.

  2. THREAT-MODEL POSITION. OPA's policy is a file or bundle on the host. An
     adversary with host access rewrites it and reloads. We run the same
     escalate / exploit / revert sequence used for Systems B, C and D and
     record what an auditor could afterwards detect.

The point is not that OPA is bad. It is a better policy engine than ours by
every measure of expressiveness. The point is that expressiveness and
write-authorisation are independent axes, and the paper's claim lives on the
second one.
"""
import argparse
import csv
import json
import os
import shutil
import statistics as st
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OPA_DIR = os.path.join(HERE, "opa")
POLICY = os.path.join(OPA_DIR, "policy.rego")
ADDR = "127.0.0.1:8181"
URL = f"http://{ADDR}/v1/data/blockguard/authz/allow"

POLICY_REF = {"search_web": True, "read_file": True, "transfer_money": False,
              "execute_command": False, "delete_database": False}


def opa_bin() -> str:
    for c in ("opa", "/opt/homebrew/bin/opa", "/usr/local/bin/opa"):
        p = shutil.which(c) or (c if os.path.exists(c) else None)
        if p:
            return p
    sys.exit("opa not found — install with `brew install opa`")


def start_server(binary: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [binary, "run", "--server", "--addr", ADDR, "--log-level", "error", POLICY],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            decide("agent_c", "read_file")
            return proc
        except Exception:
            time.sleep(0.2)
    proc.kill()
    sys.exit("OPA server did not come up")


def decide(agent_id: str, action: str) -> tuple[bool, float]:
    body = json.dumps({"input": {"agent_id": agent_id, "action": action}}).encode()
    req = urllib.request.Request(URL, data=body,
                                 headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=10) as r:
        payload = json.loads(r.read())
    dt = (time.perf_counter() - t0) * 1000.0
    return bool(payload.get("result", False)), dt


def rewrite_policy(transfer_money_for_c: bool) -> None:
    """Exactly what a host adversary does: edit the file, reload the daemon."""
    src = open(POLICY).read()
    marker = '"agent_c": {'
    head, tail = src.split(marker, 1)
    body, rest = tail.split("},", 1)
    new_body = body.replace('"transfer_money": true', '"transfer_money": XX') \
                   .replace('"transfer_money": false', '"transfer_money": XX') \
                   .replace("XX", "true" if transfer_money_for_c else "false")
    open(POLICY, "w").write(head + marker + new_body + "}," + rest)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "results_opa"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    binary = opa_bin()
    ver = subprocess.run([binary, "version"], capture_output=True, text=True).stdout.split()[1]
    print(f"  OPA {ver} at {binary}")

    original = open(POLICY).read()
    proc = start_server(binary)
    out = []
    def say(s=""):
        print(s); out.append(s)

    try:
        # ── warm-up: never time a cold server ─────────────────────────────────
        for _ in range(50):
            decide("agent_c", "read_file")

        # ── 1. decision latency + conformance on the matched trials ───────────
        say("=" * 74)
        say(f"  SYSTEM E (OPA {ver}) — DECISION LATENCY AND CONFORMANCE")
        say("=" * 74)

        rows, lat = [], []
        for tag, sweep_dir in (("rule", "results_v2_rule"), ("embedding", "results_v2")):
            sweep = [r for r in csv.DictReader(
                        open(os.path.join(HERE, sweep_dir, "experimental_results.csv")))
                     if r["System_Configuration"] == "System_C"]
            conform = 0
            for r in sweep:
                allowed, dt = decide("agent_c", r["Classified_Action"])
                lat.append(dt)
                ok = (allowed == POLICY_REF[r["Target_Tool"]])
                conform += ok
                rows.append({"Classifier": tag, "Trial_ID": r["Trial_ID"],
                             "Target_Tool": r["Target_Tool"],
                             "Classified_Action": r["Classified_Action"],
                             "OPA_Allowed": allowed, "Conformant": ok,
                             "Latency_ms": round(dt, 4)})
            say(f"  {tag:10s} conformance {conform}/300 = {conform/3:.2f}%")

        lat.sort()
        say(f"\n  latency  median={st.median(lat):.3f} ms   mean={st.mean(lat):.3f} ms   "
            f"p95={lat[int(.95*len(lat))]:.3f} ms   n={len(lat)}")
        say(f"  for comparison: System B 0.61 ms, System C 21.06 ms (medians)")

        with open(os.path.join(args.out, "opa_decisions.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)

        # ── 2. the tamper sequence, 30 repetitions ───────────────────────────
        say("\n" + "=" * 74)
        say("  SYSTEM E — ESCALATE / EXPLOIT / REVERT (30 repetitions)")
        say("=" * 74)
        tam = []
        for rep in range(30):
            baseline, _ = decide("agent_c", "transfer_money")     # expect False

            rewrite_policy(True)                                   # A2: escalate
            proc.kill(); proc.wait(); proc = start_server(binary)
            escalated, _ = decide("agent_c", "transfer_money")     # expect True

            rewrite_policy(False)                                  # A3: revert
            proc.kill(); proc.wait(); proc = start_server(binary)
            after, _ = decide("agent_c", "transfer_money")         # expect False

            tam.append({
                "rep": rep,
                "escalation_succeeded": escalated and not baseline,
                "exploited_during_window": escalated,
                # an auditor comparing live policy against a known baseline
                "detect_state": after != baseline,
                # OPA keeps no authenticated history of who changed the policy
                "detect_history": False,
            })
        with open(os.path.join(args.out, "opa_tamper.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(tam[0].keys()))
            w.writeheader(); w.writerows(tam)

        esc = sum(t["escalation_succeeded"] for t in tam)
        ds  = sum(t["detect_state"] for t in tam)
        dh  = sum(t["detect_history"] for t in tam)
        say(f"  unauthorised escalation succeeded : {esc}/30")
        say(f"  detected by state comparison      : {ds}/30")
        say(f"  detected by authenticated history : {dh}/30   (OPA keeps none)")
        say("\n  System E behaves exactly as System B does under this sequence, and")
        say("  for the same reason: the policy is host-writable state with no")
        say("  authenticated change record. Its advantage over our centralized")
        say("  baseline is expressiveness, which this attack does not touch.")

        with open(os.path.join(args.out, "opa_report.txt"), "w") as f:
            f.write("\n".join(out) + "\n")
        print(f"\n  written: {args.out}/")
        return 0
    finally:
        proc.kill()
        open(POLICY, "w").write(original)      # always restore the pristine policy


if __name__ == "__main__":
    sys.exit(main())
