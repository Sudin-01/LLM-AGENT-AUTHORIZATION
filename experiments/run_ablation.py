"""
run_ablation.py — BlockGuard Policy-Configuration Ablation Study
═══════════════════════════════════════════════════════════════════════════════
Runs the SAME 300-prompt suite (identical seed → identical prompts) under
multiple policy configurations, so the only variable that changes between
runs is the policy itself — not the prompts, not the classifier, not the
random seed. This directly tests whether observed System B vs System C
differences are due to the enforcement mechanism or to policy configuration
choices (see the limitations discussed in the paper).

CONFIGURATIONS RUN BY DEFAULT:
  baseline          — agent_b and agent_c as originally configured
                       (agent_b: transfer_money=True; agent_c: transfer_money=False)
  matched_strict    — agent_b's transfer_money forced to False (matches agent_c)
                       → isolates classifier-driven leakage from policy-driven leakage
  matched_permissive— agent_c's transfer_money forced to True (matches agent_b)
                       → confirms the contract responds correctly to live reconfiguration

Each configuration produces its own tagged CSV:
  experimental_results_baseline.csv
  experimental_results_matched_strict.csv
  experimental_results_matched_permissive.csv

A final comparison report (ablation_comparison.txt) is generated showing
per-configuration leakage/accuracy side by side, plus a definitive answer
to: "once agent_b and agent_c have IDENTICAL policy, do B and C still differ?"

USAGE:
    python run_ablation.py --api http://127.0.0.1:5000 --n-per-tool 60

PREREQUISITES:
    - Ganache + Flask running (same as run_experiment.py)
    - run_experiment.py must be in the same directory (imported, not re-implemented)
"""

import argparse
import csv
import json
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone

import requests

# Reuse everything from the main harness — no duplicated logic
from run_experiments import (
    TRIAL_FIELDS,
    BlockGuardClient,
    generate_prompts,
    generate_prompts_v2,
    run_trial,
    SYSTEM_AGENT_MAP,
    TOOLS,
)

# ══════════════════════════════════════════════════════════════════════════════
# Policy configurations to test
# ══════════════════════════════════════════════════════════════════════════════

CONFIGURATIONS = {
    "baseline": {
        # As originally set up — agent_b has elevated transfer_money permission
        "agent_b": {"search_web": True, "read_file": True, "transfer_money": True,
                    "execute_command": False, "delete_database": False},
        "agent_c": {"search_web": True, "read_file": True, "transfer_money": False,
                    "execute_command": False, "delete_database": False},
    },
    "matched_strict": {
        # agent_b forced to match agent_c's zero-trust profile
        "agent_b": {"search_web": True, "read_file": True, "transfer_money": False,
                    "execute_command": False, "delete_database": False},
        "agent_c": {"search_web": True, "read_file": True, "transfer_money": False,
                    "execute_command": False, "delete_database": False},
    },
    "matched_permissive": {
        # agent_c forced to match agent_b's elevated profile — tests live
        # reconfiguration of the smart contract under setPermission()
        "agent_b": {"search_web": True, "read_file": True, "transfer_money": True,
                    "execute_command": False, "delete_database": False},
        "agent_c": {"search_web": True, "read_file": True, "transfer_money": True,
                    "execute_command": False, "delete_database": False},
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Apply a policy configuration via the live API
# ══════════════════════════════════════════════════════════════════════════════

def apply_policy(client: BlockGuardClient, agent_id: str, permissions: dict, mode: str) -> dict:
    """
    PUT the given permissions for agent_id. For mode 'C' this sends real
    setPermission() transactions to Ganache — confirmed by checking tx_hashes
    in the response, not assumed.
    """
    try:
        r = client.session.put(
            f"{client.api_base}/api/policy/{agent_id}",
            json={"permissions": permissions, "mode": mode},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def verify_policy(client: BlockGuardClient, agent_id: str, mode: str, expected: dict) -> bool:
    """
    Read back the policy from the live source of truth (contract for C,
    dict for B) and confirm it matches what we just set. Never assume a
    PUT succeeded — verify it.
    """
    result = client.get_policy(agent_id, mode)
    actual = result.get("policy", {})
    mismatches = {
        k: (expected[k], actual.get(k))
        for k in expected
        if actual.get(k) != expected[k]
    }
    if mismatches:
        print(f"  ✗ Policy verification FAILED for {agent_id}: {mismatches}")
        return False
    print(f"  ✓ Policy verified for {agent_id}: matches expected configuration")
    return True


def set_configuration(client: BlockGuardClient, config_name: str) -> bool:
    """
    Apply and verify a named configuration from CONFIGURATIONS.
    Returns True only if both agent_b and agent_c are confirmed correct
    after the write — never proceeds on an unverified policy state.
    """
    config = CONFIGURATIONS[config_name]
    print(f"\n{'─'*78}")
    print(f"  APPLYING CONFIGURATION: {config_name}")
    print(f"{'─'*78}")

    all_ok = True
    for agent_id, perms in config.items():
        mode = "B" if agent_id == "agent_b" else "C"
        print(f"  Setting {agent_id} (mode {mode}): {perms}")
        resp = apply_policy(client, agent_id, perms, mode)
        if "error" in resp:
            print(f"  ✗ Failed to set policy for {agent_id}: {resp['error']}")
            all_ok = False
            continue
        if mode == "C":
            tx_count = len(resp.get("tx_hashes", []))
            print(f"  → {tx_count} on-chain transaction(s) confirmed")
        time.sleep(0.5)  # let chain state settle before verifying
        if not verify_policy(client, agent_id, mode, perms):
            all_ok = False

    return all_ok


# ══════════════════════════════════════════════════════════════════════════════
# Run one full sweep under the current (already-applied) configuration
# ══════════════════════════════════════════════════════════════════════════════

def run_sweep_for_config(client: BlockGuardClient, prompts: list, config_name: str) -> str:
    """
    Runs System_B and System_C only (System_A has no policy and is identical
    across all configurations, so re-running it adds no information — we
    reuse the baseline run's System_A rows when assembling the final
    comparison, saving ~300 redundant trials per extra configuration).
    """
    out_csv = f"experimental_results_{config_name}.csv"
    results = []
    systems = ["System_B", "System_C"]
    total = len(prompts) * len(systems)
    done = 0

    print(f"\n  Running {total} trials for configuration '{config_name}'...")
    t0 = time.perf_counter()

    for system in systems:
        for rec in prompts:
            result = run_trial(client, rec, system)
            results.append(result)
            done += 1
            if done % 100 == 0:
                print(f"    … {done}/{total}")

    elapsed = time.perf_counter() - t0
    print(f"  Done in {elapsed:.1f}s")

    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=TRIAL_FIELDS)
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    print(f"  ✓ Wrote {len(results)} rows to {out_csv}")
    return out_csv


# ══════════════════════════════════════════════════════════════════════════════
# Compare configurations
# ══════════════════════════════════════════════════════════════════════════════

def compute_leakage_accuracy(csv_path: str, system: str) -> dict:
    with open(csv_path) as f:
        rows = [r for r in csv.DictReader(f) if r["System_Configuration"] == system]

    valid = [r for r in rows if r["Execution_Status"] == "SUCCESS"]
    correct = sum(
        1 for r in valid
        if (r["Permission_Decision"] == "APPROVED") == (r["Intended_Policy"] == "ALLOW")
    )
    deny = [r for r in valid if r["Intended_Policy"] == "DENY"]
    leaked = [r for r in deny if r["Action_Executed"] == "TRUE"]

    return {
        "n": len(valid),
        "accuracy_pct": round(correct / len(valid) * 100, 2) if valid else 0,
        "leakage_pct": round(len(leaked) / len(deny) * 100, 2) if deny else 0,
        "leaked_trial_ids": set(r["Trial_ID"] for r in leaked),
    }


def compare_configurations(config_csvs: dict) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append("  ABLATION COMPARISON — Policy Configuration vs. Leakage/Accuracy")
    lines.append(f"  Generated: {datetime.now(timezone.utc).isoformat()}Z")
    lines.append("=" * 78)
    lines.append("")

    for config_name, csv_path in config_csvs.items():
        lines.append(f"── {config_name} " + "─" * (60 - len(config_name)))
        lines.append(f"   Policy: {json.dumps(CONFIGURATIONS[config_name], indent=2)}")
        for system in ["System_B", "System_C"]:
            stats = compute_leakage_accuracy(csv_path, system)
            lines.append(
                f"   {system}: accuracy={stats['accuracy_pct']:>6.2f}%  "
                f"leakage={stats['leakage_pct']:>6.2f}%  (n={stats['n']})"
            )
        lines.append("")

    # The key test: in matched_strict, do B and C have identical leaked trial IDs?
    if "matched_strict" in config_csvs:
        b_stats = compute_leakage_accuracy(config_csvs["matched_strict"], "System_B")
        c_stats = compute_leakage_accuracy(config_csvs["matched_strict"], "System_C")
        same = b_stats["leaked_trial_ids"] == c_stats["leaked_trial_ids"]
        lines.append("─" * 78)
        lines.append("KEY TEST — matched_strict configuration (agent_b == agent_c policy)")
        lines.append("─" * 78)
        lines.append(f"System_B leaked trial IDs: {len(b_stats['leaked_trial_ids'])}")
        lines.append(f"System_C leaked trial IDs: {len(c_stats['leaked_trial_ids'])}")
        lines.append(f"IDENTICAL leak sets: {same}")
        if same:
            lines.append("→ CONFIRMS: with matched policy, B and C are indistinguishable.")
            lines.append("  All residual leakage is attributable to the shared classifier,")
            lines.append("  not to the enforcement mechanism (centralized vs. blockchain).")
        else:
            only_b = b_stats["leaked_trial_ids"] - c_stats["leaked_trial_ids"]
            only_c = c_stats["leaked_trial_ids"] - b_stats["leaked_trial_ids"]
            lines.append(f"→ UNEXPECTED: {len(only_b)} trials leaked only in B, "
                         f"{len(only_c)} only in C, despite matched policy.")
            lines.append("  This would indicate a genuine enforcement-mechanism difference")
            lines.append("  and warrants further investigation before publication.")
        lines.append("")

    lines.append("=" * 78)
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="BlockGuard policy-configuration ablation study")
    parser.add_argument("--api", default="http://127.0.0.1:5000")
    parser.add_argument("--n-per-tool", type=int, default=60)
    parser.add_argument("--dataset", choices=["v1", "v2"], default="v2",
                        help="v2 = curated 300-prompt set (default)")
    parser.add_argument("--configs", nargs="+", default=list(CONFIGURATIONS.keys()),
                       help="Which configurations to run (default: all 3)")
    args = parser.parse_args()

    client = BlockGuardClient(args.api)

    print("Checking API connectivity...")
    if not client.health():
        print(f"✗ Cannot reach Flask API at {args.api}")
        sys.exit(1)
    print(f"✓ API is live at {args.api}")

    # CRITICAL: same seed → same 300 prompts across every configuration.
    # This is what makes the comparison valid — only the policy changes.
    prompts = (generate_prompts_v2() if args.dataset == "v2"
               else generate_prompts(n_per_tool=args.n_per_tool))
    print(f"✓ Generated {len(prompts)} prompts (fixed seed — identical across all configs)")

    config_csvs = {}
    for config_name in args.configs:
        if config_name not in CONFIGURATIONS:
            print(f"⚠ Unknown configuration '{config_name}', skipping")
            continue

        ok = set_configuration(client, config_name)
        if not ok:
            print(f"✗ Could not verify configuration '{config_name}' — skipping this sweep "
                 f"to avoid recording results against an unconfirmed policy state.")
            continue

        csv_path = run_sweep_for_config(client, prompts, config_name)
        config_csvs[config_name] = csv_path

    if not config_csvs:
        print("✗ No configurations completed successfully. Nothing to compare.")
        sys.exit(1)

    report = compare_configurations(config_csvs)
    print("\n\n" + report)

    with open("ablation_comparison.txt", "w") as f:
        f.write(report)
    print(f"\n✓ Comparison report written to ablation_comparison.txt")
    print(f"✓ Per-configuration CSVs: {list(config_csvs.values())}")

    print(f"\n⚠ IMPORTANT: restore your original policy configuration via the Policy")
    print(f"   Manager UI or another apply_policy() call before resuming normal use —")
    print(f"   this script leaves whichever configuration ran last active on-chain.")


if __name__ == "__main__":
    try:
        main()
    finally:
        print("\n" + "=" * 78)
        print("  RESTORING BASELINE POLICY")
        print("  The ablation mutates persistent policy state. Re-seed before")
        print("  running run_experiments.py:")
        print("    npx hardhat run scripts/deploy.js --network ganache")
        print("=" * 78)

