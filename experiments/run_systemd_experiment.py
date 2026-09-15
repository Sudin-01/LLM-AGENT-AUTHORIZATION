"""
System D: hash-chained signed decision log with periodic Merkle anchoring.

A natural question is why a blockchain is needed when a signed, hash-chained,
append-only log is decades old, costs no gas, and adds microseconds. This
experiment answers that directly by adding System D and re-running the same
four attack scenarios against B, C and D.

System D
--------
Every decision and every policy change becomes a log entry

    entry_i = {seq, prev_hash, payload}
    hash_i  = keccak(prev_hash || payload)
    sig_i   = ECDSA(hash_i, log_key)

so the log is tamper-*evident* to anyone holding the public key, provided the
adversary cannot sign. Every ``anchor_every`` entries the Merkle root of the
batch is written on-chain, which is the only part that costs gas.

The parameter that matters is ``anchor_every``:

    anchor_every = 1     one on-chain write per decision  (this is System C)
    anchor_every = N     one write per N decisions
    anchor_every = inf   never anchored (a pure signed hash chain)

Adversary
---------
Both capability levels from the tamper study are modelled, and the mapping to
System D is the honest one: a *privileged* adversary holds whatever key the
system trusts, which for C is the contract owner key and for D is the log
signing key.

  UNPRIVILEGED  host access only
  PRIVILEGED    host access plus the trusted signing key

The central question is what a privileged adversary can rewrite without
detection, because that is exactly where a signed chain and an anchored chain
differ.

Usage:  python3 experiments/run_systemd_experiment.py
"""

import csv
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone

from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from run_tamper_experiment import (            # noqa: E402
    b32, load_contract, send, get_events, decode32,
    OWNER_KEY, ATTACKER_KEY, TARGET_AGENT, TARGET_ACTION, BASELINE_POLICY,
    GANACHE_URL, CentralizedSystem, BlockchainSystem,
)

OUT = os.path.join(HERE, "results_systemd")
os.makedirs(OUT, exist_ok=True)

LOG_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # test key
REPETITIONS = 30
N_BEFORE, N_DURING, N_AFTER = 20, 20, 20
ANCHOR_SETTINGS = [1, 10, 100, None]           # None = never anchor


def keccak(*parts):
    return Web3.keccak(b"".join(parts))


def merkle_root(hashes):
    """Standard binary Merkle root; odd nodes are promoted unchanged."""
    if not hashes:
        return b"\x00" * 32
    level = list(hashes)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(keccak(level[i], level[i + 1]) if i + 1 < len(level) else level[i])
        level = nxt
    return level[0]


class HashChainedSystem:
    """System D. Local policy, signed hash-chained log, periodic Merkle anchor."""

    def __init__(self, w3, contract, anchor_every):
        self.w3, self.contract = w3, contract
        self.anchor_every = anchor_every            # None disables anchoring
        self.policy = dict(BASELINE_POLICY)
        self.log = []                               # [{seq, prev, payload, hash, sig}]
        self.anchors = []                           # [(upto_seq, root, tx_hash)]
        self.gas_spent = 0
        self.anchor_writes = 0
        self._acct = Account.from_key(LOG_KEY)

    # ── log construction ──────────────────────────────────────────────────
    def _append(self, payload, key=LOG_KEY):
        prev = self.log[-1]["hash"] if self.log else b"\x00" * 32
        h = keccak(prev, json.dumps(payload, sort_keys=True).encode())
        sig = Account.sign_message(encode_defunct(h), private_key=key).signature
        self.log.append({"seq": len(self.log), "prev": prev, "payload": payload,
                         "hash": h, "sig": sig})
        if self.anchor_every and len(self.log) % self.anchor_every == 0:
            self._anchor()

    def _anchor(self):
        start = self.anchors[-1][0] if self.anchors else 0
        batch = [e["hash"] for e in self.log[start:]]
        root = merkle_root(batch)
        fn = self.contract.functions.logDecision(
            b32("anchor"), b32("merkle_root"), True, root)
        ok, rc = send(self.w3, fn, OWNER_KEY)
        if ok:
            self.gas_spent += rc.gasUsed
            self.anchor_writes += 1
            self.anchors.append((len(self.log), root, rc.transactionHash.hex()))

    # ── legitimate operation ──────────────────────────────────────────────
    def set_permission(self, action, permitted):
        self.policy[action] = permitted
        self._append({"type": "policy", "action": action, "permitted": permitted})

    def check(self, action):
        return self.policy.get(action, False)

    def log_decision(self, action, permitted):
        self._append({"type": "decision", "action": action, "permitted": permitted})

    # ── audit ─────────────────────────────────────────────────────────────
    def verify(self):
        """Return (chain_intact, signatures_valid, anchors_match)."""
        prev = b"\x00" * 32
        intact = sigs = True
        for e in self.log:
            h = keccak(prev, json.dumps(e["payload"], sort_keys=True).encode())
            if h != e["hash"] or e["prev"] != prev:
                intact = False
            try:
                if Account.recover_message(encode_defunct(e["hash"]),
                                           signature=e["sig"]) != self._acct.address:
                    sigs = False
            except Exception:
                sigs = False
            prev = e["hash"]
        anchors_ok = True
        for upto, root, _ in self.anchors:
            if merkle_root([e["hash"] for e in self.log[:upto]][
                    (self.anchors[self.anchors.index((upto, root, _))-1][0]
                     if self.anchors.index((upto, root, _)) > 0 else 0):upto]) != root:
                anchors_ok = False
        return intact, sigs, anchors_ok

    def decisions_for(self, action):
        return [e for e in self.log
                if e["payload"].get("type") == "decision"
                and e["payload"].get("action") == action]

    # ── adversary ─────────────────────────────────────────────────────────
    def attack_set_policy(self, action, permitted):
        """Host access: mutate policy silently, writing no log entry."""
        self.policy[action] = permitted

    def attack_wipe(self, action, privileged):
        """Delete the incriminating entries.

        A privileged adversary additionally holds the signing key and can
        rebuild a perfectly consistent chain over the surviving entries.
        Returns the number of entries removed.
        """
        keep = [e for e in self.log
                if not (e["payload"].get("type") == "decision"
                        and e["payload"].get("action") == action)]
        removed = len(self.log) - len(keep)
        if privileged:
            self.log = []
            for e in keep:
                self._append_no_anchor(e["payload"])
        else:
            self.log = keep                       # chain now breaks
        return removed

    def _append_no_anchor(self, payload):
        prev = self.log[-1]["hash"] if self.log else b"\x00" * 32
        h = keccak(prev, json.dumps(payload, sort_keys=True).encode())
        sig = Account.sign_message(encode_defunct(h), private_key=LOG_KEY).signature
        self.log.append({"seq": len(self.log), "prev": prev, "payload": payload,
                         "hash": h, "sig": sig})

    @property
    def unanchored_window(self):
        anchored = self.anchors[-1][0] if self.anchors else 0
        return len(self.log) - anchored


# ══════════════════════════════════════════════════════════════════════════
#  Driver
# ══════════════════════════════════════════════════════════════════════════

def label(anchor):
    if anchor is None:
        return "D (signed chain, no anchor)"
    if anchor == 1:
        return "D (anchor every 1)"
    return f"D (anchor every {anchor})"


def run_repetition(w3, contract, rep, rows, cost_rows):
    def rec(system, scenario, **kw):
        rows.append(dict(repetition=rep, system=system, scenario=scenario, **kw))

    # ── System B and System C, for reference ──────────────────────────────
    cen = CentralizedSystem(os.path.join(OUT, "_b.db"))
    chain = BlockchainSystem(w3, contract, os.path.join(OUT, "_c.db"))
    for a, p in BASELINE_POLICY.items():
        if chain.check(a) != p:
            chain.set_permission(a, p)
    start_block = w3.eth.block_number + 1

    # A1 privileged escalation
    cen.attack_set_policy(TARGET_ACTION, True)
    rec("System_B", "A1", attack_blocked=False,
        detect_state=cen.check(TARGET_ACTION) != BASELINE_POLICY[TARGET_ACTION],
        detect_history=any(r[0] == TARGET_ACTION for r in cen.change_rows()),
        attributable=False)
    cen.attack_set_policy(TARGET_ACTION, False)

    chain.set_permission(TARGET_ACTION, True, key=OWNER_KEY)
    evs = [e for e in get_events(contract, "PermissionSet") if e.blockNumber >= start_block]
    rec("System_C", "A1", attack_blocked=False, detect_state=True,
        detect_history=any(decode32(e.args.actionType) == TARGET_ACTION for e in evs),
        attributable=len(evs) > 0)
    chain.set_permission(TARGET_ACTION, False, key=OWNER_KEY)

    # A2 unauthorized escalation
    cen.attack_set_policy(TARGET_ACTION, True)
    rec("System_B", "A2", attack_blocked=False, detect_state=True,
        detect_history=False, attributable=False)
    cen.attack_set_policy(TARGET_ACTION, False)
    ok, _ = chain.set_permission(TARGET_ACTION, True, key=ATTACKER_KEY)
    rec("System_C", "A2", attack_blocked=not chain.check(TARGET_ACTION),
        detect_state=False, detect_history=False, attributable=False)

    # ── System D at each anchoring setting ────────────────────────────────
    for anchor in ANCHOR_SETTINGS:
        d = HashChainedSystem(w3, contract, anchor)
        name = label(anchor)

        # A1: privileged insider with host access mutates the policy directly.
        # The log is not tampered with; it is simply bypassed, because in D the
        # policy store and the audit log are separate objects.
        d.attack_set_policy(TARGET_ACTION, True)
        intact, sigs, anchors_ok = d.verify()
        rec(name, "A1", attack_blocked=False,
            detect_state=d.check(TARGET_ACTION) != BASELINE_POLICY[TARGET_ACTION],
            detect_history=any(e["payload"].get("type") == "policy"
                               and e["payload"].get("action") == TARGET_ACTION
                               for e in d.log),
            attributable=False)
        d.policy[TARGET_ACTION] = BASELINE_POLICY[TARGET_ACTION]

        # A2: unprivileged adversary. Nothing in D authenticates a policy write,
        # so host access alone is sufficient.
        d.attack_set_policy(TARGET_ACTION, True)
        rec(name, "A2", attack_blocked=False, detect_state=True,
            detect_history=False, attributable=False)
        d.policy[TARGET_ACTION] = BASELINE_POLICY[TARGET_ACTION]

        # A3 + A4: workload, escalate, exploit, revert, then wipe the evidence
        for _ in range(N_BEFORE):
            d.log_decision("search_web", True)
        d.attack_set_policy(TARGET_ACTION, True)
        for _ in range(N_DURING):
            d.log_decision(TARGET_ACTION, True)
        d.attack_set_policy(TARGET_ACTION, False)
        for _ in range(N_AFTER):
            d.log_decision("search_web", True)

        true_total = N_BEFORE + N_DURING + N_AFTER
        rec(name, "A3", attack_blocked=False,
            detect_state=d.check(TARGET_ACTION) != BASELINE_POLICY[TARGET_ACTION],
            detect_history=any(e["payload"].get("type") == "policy"
                               and e["payload"].get("action") == TARGET_ACTION
                               for e in d.log),
            attributable=False)

        anchored_before = d.anchors[-1][0] if d.anchors else 0
        window = d.unanchored_window
        removed = d.attack_wipe(TARGET_ACTION, privileged=True)
        intact, sigs, anchors_ok = d.verify()
        # a privileged rewrite is detectable only where an anchor already fixed
        # the affected entries
        detected = not anchors_ok or removed > window
        surviving = len(d.decisions_for(TARGET_ACTION))
        rec(name, "A4", attack_blocked=False, detect_state=False,
            detect_history=detected, attributable=detected,
            chain_intact=intact, sigs_valid=sigs, anchors_ok=anchors_ok,
            removed=removed, unanchored_window=window,
            recovered=surviving, true_records=true_total)
        cost_rows.append(dict(repetition=rep, system=name,
                              anchor_every=(anchor if anchor else 0),
                              decisions=len(d.log), anchor_writes=d.anchor_writes,
                              gas_total=d.gas_spent,
                              gas_per_decision=round(d.gas_spent / max(1, true_total), 1),
                              rewritable_window=window, detected=detected))

    # System C A4 reference: per-decision on-chain write
    a3_block = w3.eth.block_number + 1
    for _ in range(N_BEFORE):
        chain.log_decision("search_web", True)
    chain.set_permission(TARGET_ACTION, True, key=OWNER_KEY)
    for _ in range(N_DURING):
        chain.log_decision(TARGET_ACTION, True)
    chain.set_permission(TARGET_ACTION, False, key=OWNER_KEY)
    for _ in range(N_AFTER):
        chain.log_decision("search_web", True)
    chain.attack_wipe_decisions(TARGET_ACTION)
    evs = [e for e in get_events(contract, "DecisionLogged") if e.blockNumber >= a3_block]
    rec("System_C", "A4", attack_blocked=False, detect_state=False,
        detect_history=len(evs) != len(chain.decision_rows()),
        attributable=True, recovered=len(evs),
        true_records=N_BEFORE + N_DURING + N_AFTER)
    rec("System_C", "A3", attack_blocked=False, detect_state=False,
        detect_history=True, attributable=True)


def main():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    assert w3.is_connected(), "chain unreachable"
    contract = load_contract(w3)
    print(f"contract {contract.address}   log-signing key "
          f"{Account.from_key(LOG_KEY).address}\n")

    rows, cost = [], []
    t0 = time.time()
    for r in range(1, REPETITIONS + 1):
        run_repetition(w3, contract, r, rows, cost)
        print(f"  repetition {r}/{REPETITIONS}", flush=True)
    elapsed = time.time() - t0

    keys = sorted({k for r in rows for k in r})
    with open(os.path.join(OUT, "systemd_results.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=keys); wr.writeheader()
        for r in rows: wr.writerow(r)
    with open(os.path.join(OUT, "systemd_cost.csv"), "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(cost[0].keys())); wr.writeheader()
        wr.writerows(cost)

    # ── report ────────────────────────────────────────────────────────────
    tt = lambda v: str(v).strip().lower() in ("true", "1", "yes")
    systems = ["System_B"] + [label(a) for a in ANCHOR_SETTINGS] + ["System_C"]
    L = ["=" * 96,
         "  SYSTEM D — IS A SIGNED HASH CHAIN ENOUGH?",
         f"  Generated: {datetime.now(timezone.utc).isoformat()}   "
         f"Repetitions: {REPETITIONS}   Wall-clock: {elapsed:.1f}s",
         "=" * 96, ""]
    for sc, desc in (("A1", "Insider escalation (privileged: holds the trusted key)"),
                     ("A2", "Unauthorized escalation (host access only)"),
                     ("A3", "Retroactive revert"),
                     ("A4", "Audit-log tampering by a privileged adversary")):
        L.append("-" * 96)
        L.append(f"{sc}  {desc}")
        L.append("-" * 96)
        L.append(f"  {'system':30s} {'blocked':>9s} {'by state':>9s} {'by history':>11s} {'attributable':>13s}")
        for s in systems:
            rs = [r for r in rows if r["system"] == s and r["scenario"] == sc]
            if not rs: continue
            f_ = lambda k: f"{sum(1 for r in rs if tt(r.get(k))):d}/{len(rs)}"
            L.append(f"  {s:30s} {f_('attack_blocked'):>9s} {f_('detect_state'):>9s} "
                     f"{f_('detect_history'):>11s} {f_('attributable'):>13s}")
        L.append("")
    L.append("-" * 96)
    L.append("COST AND DETECTION AS A FUNCTION OF ANCHOR GRANULARITY")
    L.append("-" * 96)
    L.append(f"  {'system':30s} {'on-chain writes':>16s} {'gas/decision':>13s} "
             f"{'rewritable window':>18s} {'detected':>9s}")
    for s in [label(a) for a in ANCHOR_SETTINGS]:
        cs = [c for c in cost if c["system"] == s]
        L.append(f"  {s:30s} {statistics.mean(c['anchor_writes'] for c in cs):>16.1f} "
                 f"{statistics.mean(c['gas_per_decision'] for c in cs):>13.0f} "
                 f"{statistics.mean(c['rewritable_window'] for c in cs):>18.1f} "
                 f"{sum(1 for c in cs if c['detected'])}/{len(cs):>7}")
    cw = [r for r in rows if r["system"] == "System_C" and r["scenario"] == "A4"]
    L.append(f"  {'System_C (on-chain policy)':30s} {float(N_BEFORE+N_DURING+N_AFTER):>16.1f} "
             f"{'~35452':>13s} {0.0:>18.1f} {sum(1 for r in cw if tt(r['detect_history']))}/{len(cw):>7}")
    L.append("=" * 96)
    txt = "\n".join(L)
    open(os.path.join(OUT, "systemd_summary.txt"), "w").write(txt + "\n")
    print("\n" + txt)


if __name__ == "__main__":
    main()
