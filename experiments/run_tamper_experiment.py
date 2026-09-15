"""
Tamper-resistance evaluation for BlockGuard (System B vs System C).

The main 900-trial sweeps measure *policy conformance*, where a correctly
configured centralized store and an on-chain store are provably equivalent.
This experiment measures the property that actually differentiates them:
what happens when an insider adversary tampers with the policy or the
audit trail.

To keep the comparison fair, System B is STEELMANNED: it is given its own
policy-change log and decision log in SQLite (i.e. the centralized system
does everything a well-engineered centralized system would do). The
adversary is then given identical process-level access to both systems.

Threat model
------------
The adversary has full process + filesystem access on the application host
(compromised admin account, malicious dependency, or post-RCE attacker).
Two capability levels are modelled:
  * PRIVILEGED   - additionally holds the contract owner's private key
  * UNPRIVILEGED - process access only, no owner key

Scenarios
---------
  A1  Insider privilege escalation      (adversary flips DENY -> ALLOW)
  A2  Unauthorized escalation           (same, without the owner key)
  A3  Retroactive revert                (escalate, exploit, restore policy)
  A4  Audit-log tampering               (delete the incriminating records)

Metrics
-------
  attack_succeeded        did the forbidden action become executable?
  detect_state            does comparing live policy to baseline reveal it?
  detect_history          does auditing the change history reveal it?
  attributable            can the auditor name the actor?
  reconstruction          fraction of the true decision log recoverable

Usage:  python3 experiments/run_tamper_experiment.py
"""

import csv
import json
import os
import sys
import sqlite3
import statistics
import time
from datetime import datetime, timezone

from web3 import Web3

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend"))
from policy_engine import PolicyEngine, PolicyMode, AuditStore   # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(HERE, "results_tamper")
os.makedirs(OUT, exist_ok=True)

GANACHE_URL = "http://127.0.0.1:8545"
OWNER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ATTACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

TARGET_AGENT = "agent_c"
TARGET_ACTION = "delete_database"
REPETITIONS = 30
N_BEFORE, N_DURING, N_AFTER = 20, 20, 20

BASELINE_POLICY = {
    "search_web": True, "read_file": False,
    "transfer_money": False, "execute_command": False, "delete_database": False,
}


def b32(s):
    return s.encode("utf-8")[:32].ljust(32, b"\x00")


def load_contract(w3):
    cfg = json.load(open(os.path.join(ROOT, "backend", "config.json")))
    addr = Web3.to_checksum_address(cfg["ganache"]["contractAddress"])
    art = json.load(open(os.path.join(
        ROOT, "artifacts", "contracts",
        "AgentPermissionRegistry.sol", "AgentPermissionRegistry.json")))
    return w3.eth.contract(address=addr, abi=art["abi"])


def send(w3, contract_fn, key, gas=120_000):
    """Sign and send a transaction. Returns (ok, receipt_or_error)."""
    acct = w3.eth.account.from_key(key)
    try:
        tx = contract_fn.build_transaction({
            "from": acct.address,
            "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
            "gas": gas,
            "gasPrice": w3.eth.gas_price,
        })
    except Exception as e:                       # revert caught at estimation
        return False, str(e)
    signed = w3.eth.account.sign_transaction(tx, key)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    try:
        h = w3.eth.send_raw_transaction(raw)
        rc = w3.eth.wait_for_transaction_receipt(h, timeout=30)
        return (rc.status == 1), rc
    except Exception as e:
        return False, str(e)


def get_events(contract, name):
    ev = getattr(contract.events, name)
    try:
        return ev.get_logs(from_block=0)
    except TypeError:
        return ev.get_logs(fromBlock=0)
    except Exception:
        return ev().get_logs(fromBlock=0)


# ── System B: the REAL centralized policy engine ───────────────────────────
class CentralizedSystem:
    """System B driven through the production code path.

    Earlier revisions of this harness reimplemented a centralized store, which
    left a fidelity gap: the adversary attacked a model of System B rather than
    System B. This class instead instantiates the shipped
    ``PolicyEngine(mode=CENTRALIZED)``, so policy storage, permission
    evaluation and decision logging are the same code the main sweeps use.

    The engine has no policy-change log of its own, so one is added here in the
    same SQLite file. That is the steelman: System B is credited with an audit
    facility it does not actually ship, and the adversary is still given the
    host access needed to erase it.
    """

    def __init__(self, db):
        if os.path.exists(db):
            os.remove(db)
        self.db = db
        self.engine = PolicyEngine(mode=PolicyMode.CENTRALIZED)
        self.engine.audit = AuditStore(db_path=db)          # real audit store
        self.engine.set_agent_permissions(TARGET_AGENT, dict(BASELINE_POLICY))
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS policy_changes ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT,"
                      "action_type TEXT, permitted INTEGER, ts TEXT, actor TEXT)")
            c.commit()

    # ── legitimate administration ─────────────────────────────────────────
    def set_permission(self, action, permitted, actor="admin", log=True):
        self.engine.set_agent_permissions(TARGET_AGENT, {action: permitted})
        if log:
            with sqlite3.connect(self.db) as c:
                c.execute("INSERT INTO policy_changes (agent_id,action_type,permitted,ts,actor)"
                          " VALUES (?,?,?,?,?)",
                          (TARGET_AGENT, action, int(permitted),
                           datetime.now(timezone.utc).isoformat(), actor))
                c.commit()

    def check(self, action):
        return self.engine._centralized_policy.get(TARGET_AGENT, {}).get(action, False)

    def log_decision(self, action, permitted):
        # real evaluation + real audit write
        self.engine.check_permission(TARGET_AGENT, action, request_payload="tamper-eval")

    def decision_rows(self):
        with sqlite3.connect(self.db) as c:
            return c.execute("SELECT id,action_type,permitted FROM decisions").fetchall()

    def change_rows(self):
        with sqlite3.connect(self.db) as c:
            return c.execute("SELECT action_type,permitted,actor FROM policy_changes").fetchall()

    # ── adversary capabilities (host access, no authentication) ───────────
    def attack_set_policy(self, action, permitted):
        # exactly what host-level code can do to the shipped engine: mutate the
        # in-process policy dict, leaving no record anywhere
        self.engine._centralized_policy.setdefault(TARGET_AGENT, {})[action] = permitted

    def attack_wipe_changes(self):
        with sqlite3.connect(self.db) as c:
            c.execute("DELETE FROM policy_changes"); c.commit()

    def attack_wipe_decisions(self, action):
        with sqlite3.connect(self.db) as c:
            n = c.execute("DELETE FROM decisions WHERE action_type=?", (action,)).rowcount
            c.commit()
        return n


# ── System C: on-chain policy + immutable events + same SQLite mirror ────────
class BlockchainSystem:
    def __init__(self, w3, contract, db):
        self.w3, self.contract, self.db = w3, contract, db
        if os.path.exists(db):
            os.remove(db)
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "agent_id TEXT, action_type TEXT, permitted INTEGER, ts TEXT,"
                      "tx_hash TEXT, block INTEGER)")
            c.commit()

    def set_permission(self, action, permitted, key=OWNER_KEY):
        fn = self.contract.functions.setPermission(b32(TARGET_AGENT), b32(action), permitted)
        return send(self.w3, fn, key)

    def check(self, action):
        return self.contract.functions.checkPermission(b32(TARGET_AGENT), b32(action)).call()

    def log_decision(self, action, permitted):
        rh = Web3.keccak(text=f"{TARGET_AGENT}:{action}:{time.time()}")
        fn = self.contract.functions.logDecision(
            b32(TARGET_AGENT), b32(action), permitted, rh)
        ok, rc = send(self.w3, fn, OWNER_KEY)
        if ok:
            with sqlite3.connect(self.db) as c:
                c.execute("INSERT INTO decisions (agent_id,action_type,permitted,ts,tx_hash,block)"
                          " VALUES (?,?,?,?,?,?)",
                          (TARGET_AGENT, action, int(permitted),
                           datetime.now(timezone.utc).isoformat(),
                           rc.transactionHash.hex(), rc.blockNumber))
                c.commit()
        return ok

    def decision_rows(self):
        with sqlite3.connect(self.db) as c:
            return c.execute("SELECT id,action_type,permitted FROM decisions").fetchall()

    def chain_decision_events(self):
        return get_events(self.contract, "DecisionLogged")

    def chain_permission_events(self):
        return get_events(self.contract, "PermissionSet")

    def attack_wipe_decisions(self, action):
        with sqlite3.connect(self.db) as c:
            n = c.execute("DELETE FROM decisions WHERE action_type=?", (action,)).rowcount
            c.commit()
        return n


def decode32(b):
    return bytes(b).rstrip(b"\x00").decode("utf-8", "replace")


def events_since(contract, name, from_block):
    return [e for e in get_events(contract, name) if e.blockNumber >= from_block]


def run_repetition(w3, contract, rep, rows, recon_rows):
    """One full repetition of all four attack scenarios against both systems."""
    cen = CentralizedSystem(os.path.join(OUT, "_b.db"))
    chain = BlockchainSystem(w3, contract, os.path.join(OUT, "_c.db"))

    # reset on-chain policy to baseline for this repetition
    for a, p in BASELINE_POLICY.items():
        if chain.check(a) != p:
            chain.set_permission(a, p)
    start_block = w3.eth.block_number + 1

    def rec(scenario, system, **kw):
        rows.append(dict(repetition=rep, scenario=scenario, system=system, **kw))

    # ── A1: insider privilege escalation (adversary holds owner key) ─────────
    cen.attack_set_policy(TARGET_ACTION, True)          # silent, bypasses change log
    t0 = time.perf_counter()
    b_state = cen.check(TARGET_ACTION) != BASELINE_POLICY[TARGET_ACTION]
    b_hist = any(r[0] == TARGET_ACTION for r in cen.change_rows())
    b_audit_ms = (time.perf_counter() - t0) * 1000
    rec("A1_insider_escalation", "System_B", attack_succeeded=cen.check(TARGET_ACTION),
        detect_state=b_state, detect_history=b_hist, attributable=b_hist,
        audit_ms=round(b_audit_ms, 3))

    chain.set_permission(TARGET_ACTION, True, key=OWNER_KEY)
    t0 = time.perf_counter()
    c_state = chain.check(TARGET_ACTION) != BASELINE_POLICY[TARGET_ACTION]
    evs = events_since(contract, "PermissionSet", start_block)
    c_hist = any(decode32(e.args.actionType) == TARGET_ACTION for e in evs)
    actors = set()
    for e in evs:
        actors.add(w3.eth.get_transaction(e.transactionHash)["from"])
    c_audit_ms = (time.perf_counter() - t0) * 1000
    rec("A1_insider_escalation", "System_C", attack_succeeded=chain.check(TARGET_ACTION),
        detect_state=c_state, detect_history=c_hist, attributable=len(actors) > 0,
        audit_ms=round(c_audit_ms, 3))

    # restore
    cen.attack_set_policy(TARGET_ACTION, False)
    chain.set_permission(TARGET_ACTION, False, key=OWNER_KEY)

    # ── A2: unauthorized escalation (no owner key) ───────────────────────────
    cen.attack_set_policy(TARGET_ACTION, True)          # no authn concept at all
    rec("A2_unauthorized_escalation", "System_B",
        attack_succeeded=cen.check(TARGET_ACTION), detect_state=True,
        detect_history=False, attributable=False, audit_ms=0.0)
    cen.attack_set_policy(TARGET_ACTION, False)

    ok, _ = chain.set_permission(TARGET_ACTION, True, key=ATTACKER_KEY)
    rec("A2_unauthorized_escalation", "System_C",
        attack_succeeded=chain.check(TARGET_ACTION), detect_state=False,
        detect_history=False, attributable=False, audit_ms=0.0)

    # ── A3 + A4: escalate -> exploit -> revert, then wipe the evidence ───────
    a3_block = w3.eth.block_number + 1

    for _ in range(N_BEFORE):                            # benign traffic
        cen.log_decision("search_web", True)
        chain.log_decision("search_web", True)

    cen.attack_set_policy(TARGET_ACTION, True)
    chain.set_permission(TARGET_ACTION, True, key=OWNER_KEY)
    for _ in range(N_DURING):                            # the exploit window
        cen.log_decision(TARGET_ACTION, True)
        chain.log_decision(TARGET_ACTION, True)
    cen.attack_set_policy(TARGET_ACTION, False)          # cover tracks
    chain.set_permission(TARGET_ACTION, False, key=OWNER_KEY)

    for _ in range(N_AFTER):
        cen.log_decision("search_web", True)
        chain.log_decision("search_web", True)

    true_total = N_BEFORE + N_DURING + N_AFTER

    # A3 measured BEFORE log tampering: state is back to baseline in both
    t0 = time.perf_counter()
    b_state_clean = cen.check(TARGET_ACTION) == BASELINE_POLICY[TARGET_ACTION]
    b_hist3 = any(r[0] == TARGET_ACTION for r in cen.change_rows())
    b_ms = (time.perf_counter() - t0) * 1000
    rec("A3_retroactive_revert", "System_B", attack_succeeded=True,
        detect_state=not b_state_clean, detect_history=b_hist3,
        attributable=b_hist3, audit_ms=round(b_ms, 3))

    t0 = time.perf_counter()
    c_state_clean = chain.check(TARGET_ACTION) == BASELINE_POLICY[TARGET_ACTION]
    evs3 = [e for e in events_since(contract, "PermissionSet", a3_block)
            if decode32(e.args.actionType) == TARGET_ACTION]
    c_hist3 = len(evs3) >= 2                              # escalate + revert both recorded
    actors3 = {w3.eth.get_transaction(e.transactionHash)["from"] for e in evs3}
    c_ms = (time.perf_counter() - t0) * 1000
    rec("A3_retroactive_revert", "System_C", attack_succeeded=True,
        detect_state=not c_state_clean, detect_history=c_hist3,
        attributable=len(actors3) > 0, audit_ms=round(c_ms, 3))

    # ── A4: adversary deletes the incriminating audit records ───────────────
    cen.attack_wipe_decisions(TARGET_ACTION)
    cen.attack_wipe_changes()
    chain.attack_wipe_decisions(TARGET_ACTION)

    t0 = time.perf_counter()
    b_rows = len(cen.decision_rows())
    b_recon = b_rows                                      # nothing else to recover from
    b_detect = False                                      # no independent reference exists
    b_ms = (time.perf_counter() - t0) * 1000
    rec("A4_audit_log_tampering", "System_B", attack_succeeded=True,
        detect_state=False, detect_history=False, attributable=False,
        audit_ms=round(b_ms, 3))
    recon_rows.append(dict(repetition=rep, system="System_B", true_records=true_total,
                           surviving_mirror_rows=b_rows, recovered_records=b_recon,
                           attack_window_records=N_DURING,
                           attack_window_recovered=0,
                           reconstruction_pct=round(100 * b_recon / true_total, 2),
                           tampering_detected=b_detect, audit_ms=round(b_ms, 3)))

    t0 = time.perf_counter()
    c_rows = len(chain.decision_rows())
    chain_evs = events_since(contract, "DecisionLogged", a3_block)
    c_recon = len(chain_evs)
    c_window = sum(1 for e in chain_evs if decode32(e.args.actionType) == TARGET_ACTION)
    c_detect = c_recon != c_rows                          # mirror vs chain mismatch
    c_ms = (time.perf_counter() - t0) * 1000
    rec("A4_audit_log_tampering", "System_C", attack_succeeded=True,
        detect_state=False, detect_history=c_detect, attributable=c_detect,
        audit_ms=round(c_ms, 3))
    recon_rows.append(dict(repetition=rep, system="System_C", true_records=true_total,
                           surviving_mirror_rows=c_rows, recovered_records=c_recon,
                           attack_window_records=N_DURING,
                           attack_window_recovered=c_window,
                           reconstruction_pct=round(100 * c_recon / true_total, 2),
                           tampering_detected=c_detect, audit_ms=round(c_ms, 3)))


def main():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    assert w3.is_connected(), "Ganache not reachable at " + GANACHE_URL
    contract = load_contract(w3)
    print(f"chain id {w3.eth.chain_id}  contract {contract.address}")
    print(f"owner    {w3.eth.account.from_key(OWNER_KEY).address}")
    print(f"attacker {w3.eth.account.from_key(ATTACKER_KEY).address}\n")

    rows, recon = [], []
    t_start = time.time()
    for r in range(1, REPETITIONS + 1):
        run_repetition(w3, contract, r, rows, recon)
        print(f"  repetition {r}/{REPETITIONS} complete", flush=True)
    elapsed = time.time() - t_start

    with open(os.path.join(OUT, "tamper_results.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(rows[0].keys())); wr.writeheader()
        wr.writerows(rows)
    with open(os.path.join(OUT, "reconstruction.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(recon[0].keys())); wr.writeheader()
        wr.writerows(recon)

    # ── summary ─────────────────────────────────────────────────────────────
    L = []
    L.append("=" * 78)
    L.append("  BLOCKGUARD TAMPER-RESISTANCE EVALUATION")
    L.append(f"  Generated: {datetime.now(timezone.utc).isoformat()}")
    L.append(f"  Repetitions: {REPETITIONS}   Wall-clock: {elapsed:.1f}s")
    L.append(f"  Workload per repetition: {N_BEFORE} benign + {N_DURING} exploit"
             f" + {N_AFTER} benign = {N_BEFORE+N_DURING+N_AFTER} decisions")
    L.append("  System B is steelmanned: it keeps its own policy-change log and")
    L.append("  decision log in SQLite. Adversary has identical process access to both.")
    L.append("=" * 78)

    scenarios = ["A1_insider_escalation", "A2_unauthorized_escalation",
                 "A3_retroactive_revert", "A4_audit_log_tampering"]
    titles = {
        "A1_insider_escalation": "A1  Insider privilege escalation (adversary holds owner key)",
        "A2_unauthorized_escalation": "A2  Unauthorized escalation (process access, no owner key)",
        "A3_retroactive_revert": "A3  Retroactive revert (escalate -> exploit -> restore policy)",
        "A4_audit_log_tampering": "A4  Audit-log tampering (delete incriminating records)",
    }
    for sc in scenarios:
        L.append("")
        L.append("-" * 78)
        L.append(titles[sc])
        L.append("-" * 78)
        L.append(f"  {'System':10s} {'attack ok':>10s} {'by state':>10s} "
                 f"{'by history':>11s} {'attributable':>13s} {'audit ms':>10s}")
        for sysname in ("System_B", "System_C"):
            rs = [r for r in rows if r["scenario"] == sc and r["system"] == sysname]
            n = len(rs)
            f = lambda k: f"{sum(1 for r in rs if r[k])}/{n}"
            ms = statistics.median(r["audit_ms"] for r in rs)
            L.append(f"  {sysname:10s} {f('attack_succeeded'):>10s} {f('detect_state'):>10s} "
                     f"{f('detect_history'):>11s} {f('attributable'):>13s} {ms:>10.3f}")

    L.append("")
    L.append("-" * 78)
    L.append("FORENSIC RECONSTRUCTION AFTER AUDIT-LOG TAMPERING")
    L.append("-" * 78)
    for sysname in ("System_B", "System_C"):
        rs = [r for r in recon if r["system"] == sysname]
        pct = statistics.mean(r["reconstruction_pct"] for r in rs)
        win = statistics.mean(r["attack_window_recovered"] for r in rs)
        det = sum(1 for r in rs if r["tampering_detected"])
        L.append(f"  {sysname}:  overall records recovered {pct:.2f}%   "
                 f"exploit-window records recovered {win:.1f}/{N_DURING}   "
                 f"tampering detected {det}/{len(rs)}")
    L.append("=" * 78)

    txt = "\n".join(L)
    open(os.path.join(OUT, "tamper_summary.txt"), "w").write(txt + "\n")
    print("\n" + txt)
    print(f"\nResults written to {OUT}")


if __name__ == "__main__":
    main()

# Scratch SQLite files (_b.db, _c.db) are recreated on each run and are not
# part of the results; they are removed from version control.
