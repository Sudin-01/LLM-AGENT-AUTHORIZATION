# """
# backend/app.py
# Flask REST API — serves the BlockGuard frontend and experiment harness.

# Endpoints:
#   POST /api/request          — submit agent action request
#   GET  /api/audit            — retrieve audit log
#   GET  /api/stats            — aggregate statistics
#   GET  /api/policy/<agent>   — read current policy for agent
#   PUT  /api/policy/<agent>   — update policy for agent
#   GET  /api/blockchain/info  — blockchain / contract status
#   POST /api/experiment/run   — run full 3-system experiment
#   GET  /api/experiment/results — get latest experiment results

# Run:
#   pip install flask flask-cors web3
#   python backend/app.py
# """

# import os
# import json
# import time
# import hashlib
# import random
# from datetime import datetime
# from flask import Flask, request, jsonify
# from flask_cors import CORS

# # ── Local imports ──────────────────────────────────────────────────────────────
# try:
#     from policy_engine import PolicyEngine, PolicyMode
#     from agent import AgentRunner, AgentMode, TOOLS
# except ImportError:
#     import sys
#     sys.path.insert(0, os.path.dirname(__file__))
#     from policy_engine import PolicyEngine, PolicyMode
#     from agent import AgentRunner, AgentMode, TOOLS

# app = Flask(__name__)
# CORS(app)

# # ── Config ─────────────────────────────────────────────────────────────────────
# GANACHE_URL     = os.getenv("GANACHE_URL", "http://127.0.0.1:8545")
# CONTRACT_ADDR   = os.getenv("CONTRACT_ADDRESS", "")  # Set after deploy
# DEPLOYER_KEY    = os.getenv("DEPLOYER_PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
# OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "")

# # Config file (written by deploy.js)
# _config_path = os.path.join(os.path.dirname(__file__), "config.json")
# if os.path.exists(_config_path) and not CONTRACT_ADDR:
#     with open(_config_path) as f:
#         _cfg = json.load(f)
#     CONTRACT_ADDR = _cfg.get("ganache", {}).get("contractAddress", "")

# # ── Engine pool — one engine per mode ─────────────────────────────────────────
# _engines = {}
# _runners = {}

# def get_engine(mode_char: str) -> PolicyEngine:
#     if mode_char not in _engines:
#         mode = {"A": PolicyMode.BASELINE, "B": PolicyMode.CENTRALIZED, "C": PolicyMode.BLOCKCHAIN}[mode_char]
#         kwargs = {"mode": mode}
#         if mode == PolicyMode.BLOCKCHAIN:
#             kwargs["ganache_url"]          = GANACHE_URL
#             kwargs["contract_address"]     = CONTRACT_ADDR or None
#             kwargs["deployer_private_key"] = DEPLOYER_KEY or None
#         _engines[mode_char] = PolicyEngine(**kwargs)
#     return _engines[mode_char]

# def get_runner(mode_char: str, agent_id: str) -> AgentRunner:
#     key = f"{mode_char}:{agent_id}"
#     if key not in _runners:
#         mode = {"A": AgentMode.BASELINE, "B": AgentMode.CENTRALIZED, "C": AgentMode.BLOCKCHAIN}[mode_char]
#         _runners[key] = AgentRunner(
#             mode=mode,
#             policy_engine=get_engine(mode_char),
#             agent_id=agent_id,
#             openai_api_key=OPENAI_API_KEY or None,
#         )
#     return _runners[key]

# # ══════════════════════════════════════════════════════════════════════════════
# # Routes
# # ══════════════════════════════════════════════════════════════════════════════

# @app.route("/api/health")
# def health():
#     return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


# @app.route("/api/request", methods=["POST"])
# def handle_request():
#     """
#     Submit an agent action request.
#     Body: { "request": str, "agent_id": str, "mode": "A"|"B"|"C" }
#     """
#     data = request.get_json(force=True)
#     user_request = data.get("request", "").strip()
#     agent_id     = data.get("agent_id", "agent_a")
#     mode_char    = data.get("mode", "C").upper()

#     if not user_request:
#         return jsonify({"error": "request field is required"}), 400
#     if mode_char not in ("A", "B", "C"):
#         return jsonify({"error": "mode must be A, B, or C"}), 400

#     try:
#         runner = get_runner(mode_char, agent_id)
#         result = runner.run(user_request, agent_id=agent_id)
#         return jsonify(result.to_dict())
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route("/api/audit")
# def get_audit():
#     """Return the last 200 audit log entries (all modes merged)."""
#     mode_char = request.args.get("mode", "C").upper()
#     try:
#         engine = get_engine(mode_char)
#         return jsonify(engine.get_audit_log())
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route("/api/stats")
# def get_stats():
#     """Aggregate stats for all three modes."""
#     out = {}
#     for m in ("A", "B", "C"):
#         try:
#             engine = get_engine(m)
#             local  = engine.get_stats()
#             chain  = engine.get_blockchain_stats()
#             out[m] = {"local_db": local, "blockchain": chain}
#         except Exception as e:
#             out[m] = {"error": str(e)}
#     return jsonify(out)


# # @app.route("/api/policy/<agent_id>", methods=["GET"])
# # def get_policy(agent_id):
# #     """Return the current policy for an agent."""
# #     from policy_engine import DEFAULT_CENTRALIZED_POLICY
# #     engine = get_engine("B")
# #     policy = engine._centralized_policy.get(agent_id, {})
# #     return jsonify({"agent_id": agent_id, "policy": policy})


# # @app.route("/api/policy/<agent_id>", methods=["PUT"])
# # def update_policy(agent_id):
# #     """
# #     Update permissions for an agent.
# #     Body: { "permissions": { "search_web": true, "delete_database": false, ... }, "mode": "B"|"C" }
# #     """
# #     data        = request.get_json(force=True)
# #     permissions = data.get("permissions", {})
# #     mode_char   = data.get("mode", "C").upper()

# #     if not permissions:
# #         return jsonify({"error": "permissions field required"}), 400

# #     try:
# #         engine = get_engine(mode_char)
# #         engine.set_agent_permissions(agent_id, permissions)
# #         return jsonify({
# #             "status": "updated",
# #             "agent_id": agent_id,
# #             "mode": mode_char,
# #             "permissions": permissions
# #         })
# #     except Exception as e:
# #         return jsonify({"error": str(e)}), 500

# @app.route("/api/policy/<agent_id>", methods=["GET"])
# def get_policy(agent_id):
#     m = request.args.get("mode", "C").upper()
#     ACTIONS = ["search_web","read_file","transfer_money","execute_command","delete_database"]
#     eng = get_engine(m)

#     if m == "C" and eng._blockchain_ready:
#         policy = {}
#         for action in ACTIONS:
#             try:
#                 ab = eng._to_bytes32(agent_id)
#                 ac = eng._to_bytes32(action)
#                 policy[action] = eng.contract.functions.checkPermission(ab, ac).call()
#             except Exception:
#                 policy[action] = False
#         return jsonify({"agent_id": agent_id, "policy": policy, "source": "blockchain"})
#     else:
#         policy = eng._centralized_policy.get(agent_id, {a: False for a in ACTIONS})
#         return jsonify({"agent_id": agent_id, "policy": policy, "source": "centralized"})


# @app.route("/api/policy/<agent_id>", methods=["PUT"])
# def update_policy(agent_id):
#     data        = request.get_json(force=True)
#     permissions = data.get("permissions", {})
#     m           = data.get("mode", "C").upper()
#     if not permissions:
#         return jsonify({"error": "permissions required"}), 400

#     eng = get_engine(m)
#     tx_hashes = []

#     if m == "C" and eng._blockchain_ready:
#         deployer_addr = (
#             eng.deployer_account if isinstance(eng.deployer_account, str)
#             else eng.deployer_account.address
#         )
#         for action, permitted in permissions.items():
#             try:
#                 ab = eng._to_bytes32(agent_id)
#                 ac = eng._to_bytes32(action)
#                 tx = eng.contract.functions.setPermission(ab, ac, permitted).build_transaction({
#                     "from":     deployer_addr,
#                     "nonce":    eng.w3.eth.get_transaction_count(deployer_addr),
#                     "gas":      100_000,
#                     "gasPrice": eng.w3.to_wei("20", "gwei"),
#                 })
#                 signed  = eng.w3.eth.account.sign_transaction(tx, eng.deployer_account.key)
#                 raw     = eng.w3.eth.send_raw_transaction(signed.rawTransaction)
#                 receipt = eng.w3.eth.wait_for_transaction_receipt(raw)
#                 tx_hashes.append(receipt.transactionHash.hex())
#                 # This line prints in your Ganache terminal
#                 print(f"[BlockGuard] setPermission({agent_id}, {action}, {permitted}) "
#                       f"→ tx {receipt.transactionHash.hex()} block #{receipt.blockNumber}")
#             except Exception as e:
#                 print(f"[BlockGuard] setPermission error for {action}: {e}")

#         return jsonify({
#             "status":      "updated",
#             "agent_id":    agent_id,
#             "mode":        m,
#             "permissions": permissions,
#             "tx_hashes":   tx_hashes,
#             "tx_hash":     tx_hashes[0] if tx_hashes else None,
#         })
#     else:
#         eng.set_agent_permissions(agent_id, permissions)
#         return jsonify({"status": "updated", "agent_id": agent_id, "mode": m, "permissions": permissions})
# @app.route("/api/blockchain/info")
# def blockchain_info():
#     """Return blockchain / contract connection status."""
#     engine = get_engine("C")
#     info = {
#         "ganache_url":      GANACHE_URL,
#         "contract_address": CONTRACT_ADDR,
#         "blockchain_ready": engine._blockchain_ready,
#         "web3_available":   engine.w3 is not None,
#     }
#     if engine._blockchain_ready:
#         try:
#             info["block_number"]  = engine.w3.eth.block_number
#             info["chain_id"]      = engine.w3.eth.chain_id
#             info["owner_address"] = engine.contract.functions.owner().call()
#             d, dn = engine.contract.functions.getStats().call()
#             info["on_chain_decisions"] = d
#             info["on_chain_denials"]   = dn
#         except Exception as e:
#             info["error"] = str(e)
#     return jsonify(info)


# @app.route("/api/experiment/run", methods=["POST"])
# def run_experiment_endpoint():
#     """
#     Run the full 3-system experiment (simulated).
#     Body: { "n_per_action": 60 }
#     """
#     import sys, os
#     sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../experiments"))
#     from run_experiments import run_experiment, run_scalability_experiment, run_gas_experiment
#     from dataclasses import asdict

#     data        = request.get_json(force=True) or {}
#     n_per_action = int(data.get("n_per_action", 60))

#     try:
#         exp_data   = run_experiment(n_per_action=n_per_action)
#         scalability = run_scalability_experiment()
#         gas        = run_gas_experiment()
#         summaries  = {k: asdict(v) for k, v in exp_data["summaries"].items()}
#         return jsonify({
#             "summaries": summaries,
#             "scalability": scalability,
#             "gas": gas,
#             "generated_at": datetime.utcnow().isoformat() + "Z",
#         })
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500


# @app.route("/api/experiment/results")
# def get_experiment_results():
#     """Return cached experiment results if available."""
#     path = "/tmp/experiment_output.json"
#     if os.path.exists(path):
#         with open(path) as f:
#             return jsonify(json.load(f))
#     return jsonify({"error": "No results yet. POST /api/experiment/run first."}), 404


# # ══════════════════════════════════════════════════════════════════════════════
# # Entry point
# # ══════════════════════════════════════════════════════════════════════════════

# if __name__ == "__main__":
#     port = int(os.getenv("PORT", 5000))
#     debug = os.getenv("FLASK_DEBUG", "1") == "1"
#     print(f"[BlockGuard API] Starting on port {port}")
#     print(f"[BlockGuard API] Ganache URL:      {GANACHE_URL}")
#     print(f"[BlockGuard API] Contract address: {CONTRACT_ADDR or '(not set — deploy first)'}")
#     app.run(host="0.0.0.0", port=port, debug=debug)
"""
backend/app.py  —  BlockGuard REST API
"""

import os
import json
import sys
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from policy_engine import PolicyEngine, PolicyMode, DEFAULT_CENTRALIZED_POLICY
from agent import AgentRunner, AgentMode

app  = Flask(__name__)
CORS(app)

# ── Config ────────────────────────────────────────────────────────────────────
def _experiment_output_path():
    """Scratch path for experiment output; honours BLOCKGUARD_DATA_DIR."""
    import tempfile
    base = os.getenv("BLOCKGUARD_DATA_DIR") or tempfile.gettempdir()
    return os.path.join(base, "experiment_output.json")


GANACHE_URL  = os.getenv("GANACHE_URL",            "http://127.0.0.1:8545")
CONTRACT_ADDR= os.getenv("CONTRACT_ADDRESS",       "")
DEPLOYER_KEY = os.getenv("DEPLOYER_PRIVATE_KEY",
    # Hardhat/Ganache deterministic account #0 — safe for local dev only
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
OPENAI_KEY   = os.getenv("OPENAI_API_KEY",         "")

# Read contract address from config.json written by deploy.js
_cfg = os.path.join(os.path.dirname(__file__), "config.json")
if os.path.exists(_cfg) and not CONTRACT_ADDR:
    with open(_cfg) as f:
        CONTRACT_ADDR = json.load(f).get("ganache", {}).get("contractAddress", "")

# ── Engine / runner pool ──────────────────────────────────────────────────────
_engines: dict[str, PolicyEngine] = {}
_runners: dict[str, AgentRunner]  = {}

def get_engine(m: str) -> PolicyEngine:
    if m not in _engines:
        mode = {"A": PolicyMode.BASELINE,
                "B": PolicyMode.CENTRALIZED,
                "C": PolicyMode.BLOCKCHAIN}[m]
        kw = {"mode": mode}
        if m == "C":
            kw["ganache_url"]          = GANACHE_URL
            kw["contract_address"]     = CONTRACT_ADDR or None
            kw["deployer_private_key"] = DEPLOYER_KEY or None
        _engines[m] = PolicyEngine(**kw)
    return _engines[m]

def get_runner(m: str, agent_id: str) -> AgentRunner:
    key = f"{m}:{agent_id}"
    if key not in _runners:
        mode = {"A": AgentMode.BASELINE,
                "B": AgentMode.CENTRALIZED,
                "C": AgentMode.BLOCKCHAIN}[m]
        _runners[key] = AgentRunner(
            mode=mode,
            policy_engine=get_engine(m),
            agent_id=agent_id,
            openai_api_key=OPENAI_KEY or None,
        )
    return _runners[key]

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


@app.route("/api/request", methods=["POST"])
def handle_request():
    data     = request.get_json(force=True)
    req      = data.get("request", "").strip()
    agent_id = data.get("agent_id", "agent_a")
    m        = data.get("mode", "C").upper()
    if not req:
        return jsonify({"error": "request is required"}), 400
    if m not in ("A", "B", "C"):
        return jsonify({"error": "mode must be A, B or C"}), 400
    try:
        return jsonify(get_runner(m, agent_id).run(req, agent_id=agent_id).to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit")
def get_audit():
    m = request.args.get("mode", "C").upper()
    try:
        return jsonify(get_engine(m).get_audit_log())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats")
def get_stats():
    out = {}
    for m in ("A", "B", "C"):
        try:
            eng  = get_engine(m)
            out[m] = {"local_db": eng.get_stats(), "blockchain": eng.get_blockchain_stats()}
        except Exception as e:
            out[m] = {"error": str(e)}
    return jsonify(out)


@app.route("/api/policy/<agent_id>", methods=["GET"])
def get_policy(agent_id):
    m       = request.args.get("mode", "C").upper()
    ACTIONS = ["search_web","read_file","transfer_money","execute_command","delete_database"]
    eng     = get_engine(m)

    if m == "C" and eng._blockchain_ready:
        policy = {}
        for action in ACTIONS:
            try:
                policy[action] = eng.contract.functions.checkPermission(
                    eng._to_bytes32(agent_id), eng._to_bytes32(action)
                ).call()
            except Exception:
                policy[action] = False
        return jsonify({"agent_id": agent_id, "policy": policy, "source": "blockchain"})
    else:
        policy = eng._centralized_policy.get(agent_id, {a: False for a in ACTIONS})
        return jsonify({"agent_id": agent_id, "policy": policy, "source": "centralized"})


@app.route("/api/policy/<agent_id>", methods=["PUT"])
def update_policy(agent_id):
    data        = request.get_json(force=True)
    permissions = data.get("permissions", {})
    m           = data.get("mode", "C").upper()
    if not permissions:
        return jsonify({"error": "permissions required"}), 400

    eng       = get_engine(m)
    tx_hashes = []

    if m == "C" and eng._blockchain_ready:
        failed = []
        for action, permitted in permissions.items():
            ab = eng._to_bytes32(agent_id)
            ac = eng._to_bytes32(action)
            fn = eng.contract.functions.setPermission(ab, ac, permitted)
            receipt = eng._send_tx(fn, gas=100_000)
            if receipt:
                tx_hashes.append(receipt.transactionHash.hex())
                print(f"[BlockGuard] setPermission({agent_id},{action},{permitted}) "
                      f"→ block #{receipt.blockNumber}")
            else:
                failed.append(action)
        if failed:
            return jsonify({
                "error": f"on-chain setPermission failed for: {', '.join(failed)} "
                         "(see server log for the transaction error)",
                "agent_id": agent_id, "mode": m,
                "tx_hashes": tx_hashes,
            }), 502
        return jsonify({
            "status": "updated", "agent_id": agent_id, "mode": m,
            "permissions": permissions,
            "tx_hashes": tx_hashes,
            "tx_hash":   tx_hashes[0] if tx_hashes else None,
        })
    else:
        eng.set_agent_permissions(agent_id, permissions)
        return jsonify({"status": "updated", "agent_id": agent_id,
                        "mode": m, "permissions": permissions})


@app.route("/api/blockchain/info")
def blockchain_info():
    eng  = get_engine("C")
    info = {
        "ganache_url":      GANACHE_URL,
        "contract_address": CONTRACT_ADDR,
        "blockchain_ready": eng._blockchain_ready,
    }
    if eng._blockchain_ready:
        try:
            info["block_number"]       = eng.w3.eth.block_number
            info["chain_id"]           = eng.w3.eth.chain_id
            info["owner_address"]      = eng.contract.functions.owner().call()
            d, dn = eng.contract.functions.getStats().call()
            info["on_chain_decisions"] = d
            info["on_chain_denials"]   = dn
        except Exception as e:
            info["chain_error"] = str(e)
    return jsonify(info)


@app.route("/api/experiment/run", methods=["POST"])
def run_experiment():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../experiments"))
    from run_experiments import (run_experiment as _run,
                                  run_scalability_experiment,
                                  run_gas_experiment)
    from dataclasses import asdict
    n = int((request.get_json(force=True) or {}).get("n_per_action", 60))
    try:
        exp   = _run(n_per_action=n)
        out   = {
            "summaries":   {k: asdict(v) for k, v in exp["summaries"].items()},
            "scalability": run_scalability_experiment(),
            "gas":         run_gas_experiment(),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }
        with open(_experiment_output_path(), "w") as f:
            json.dump(out, f)
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/experiment/results")
def experiment_results():
    p = _experiment_output_path()
    if os.path.exists(p):
        with open(p) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "Run POST /api/experiment/run first"}), 404


# ── Boot ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    print(f"\n[BlockGuard] API     → http://127.0.0.1:{port}/api/health")
    print(f"[BlockGuard] Ganache → {GANACHE_URL}")
    print(f"[BlockGuard] Contract→ {CONTRACT_ADDR or '(not set — run deploy.js first)'}")
    print(f"[BlockGuard] Deployer→ {DEPLOYER_KEY[:10]}…\n")
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)