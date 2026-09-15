# """
# policy_engine.py
# Blockchain-based policy enforcement engine for autonomous AI agents.

# Interfaces with a deployed AgentPermissionRegistry smart contract via web3.py.
# Provides:
#   - Permission checking (view call, zero gas)
#   - Decision logging (on-chain audit trail)
#   - Centralized JSON fallback (System B comparison)
#   - Unrestricted baseline (System A comparison)
# """

# from curses import raw
# import time
# import json
# import hashlib
# try:
#     from eth_hash.auto import keccak
#     HAS_KECCAK = True
# except ImportError:
#     HAS_KECCAK = False

# import sqlite3
# import os
# import tempfile
import threading
# from enum import Enum
# from dataclasses import dataclass, field, asdict
# from typing import Optional
# from datetime import datetime

# # ── Optional web3 import ───────────────────────────────────────────────────────
# try:
#     from web3 import Web3
#     from web3.middleware import geth_poa_middleware
#     WEB3_AVAILABLE = True
# except ImportError:
#     WEB3_AVAILABLE = False

# # ══════════════════════════════════════════════════════════════════════════════
# # Constants
# # ══════════════════════════════════════════════════════════════════════════════

# # Canonical action types — must match what the smart contract understands
# ACTION_TYPES = {
#     "SEARCH_WEB":       "search_web",
#     "READ_FILE":        "read_file",
#     "TRANSFER_MONEY":   "transfer_money",
#     "EXECUTE_COMMAND":  "execute_command",
#     "DELETE_DATABASE":  "delete_database",
# }

# # Default policy for System B (centralized JSON)
# DEFAULT_CENTRALIZED_POLICY = {
#     "agent_a": {
#         "search_web":       True,
#         "read_file":        True,
#         "transfer_money":   False,
#         "execute_command":  False,
#         "delete_database":  False,
#     }
# }

# # Minimal ABI for AgentPermissionRegistry
# CONTRACT_ABI = [
#     {
#         "inputs": [
#             {"internalType": "bytes32", "name": "agentId", "type": "bytes32"},
#             {"internalType": "bytes32", "name": "actionType", "type": "bytes32"},
#             {"internalType": "bool", "name": "permitted", "type": "bool"}
#         ],
#         "name": "setPermission",
#         "outputs": [],
#         "stateMutability": "nonpayable",
#         "type": "function"
#     },
#     {
#         "inputs": [
#             {"internalType": "bytes32[]", "name": "agentIds", "type": "bytes32[]"},
#             {"internalType": "bytes32[]", "name": "actionTypes", "type": "bytes32[]"},
#             {"internalType": "bool[]", "name": "permittedFlags", "type": "bool[]"}
#         ],
#         "name": "batchSetPermissions",
#         "outputs": [],
#         "stateMutability": "nonpayable",
#         "type": "function"
#     },
#     {
#         "inputs": [
#             {"internalType": "bytes32", "name": "agentId", "type": "bytes32"},
#             {"internalType": "bytes32", "name": "actionType", "type": "bytes32"}
#         ],
#         "name": "checkPermission",
#         "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "inputs": [
#             {"internalType": "bytes32", "name": "agentId", "type": "bytes32"},
#             {"internalType": "bytes32", "name": "actionType", "type": "bytes32"},
#             {"internalType": "bool", "name": "permitted", "type": "bool"},
#             {"internalType": "bytes32", "name": "requestHash", "type": "bytes32"}
#         ],
#         "name": "logDecision",
#         "outputs": [],
#         "stateMutability": "nonpayable",
#         "type": "function"
#     },
#     {
#         "inputs": [],
#         "name": "getStats",
#         "outputs": [
#             {"internalType": "uint256", "name": "decisions", "type": "uint256"},
#             {"internalType": "uint256", "name": "denials", "type": "uint256"}
#         ],
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "inputs": [],
#         "name": "owner",
#         "outputs": [{"internalType": "address", "name": "", "type": "address"}],
#         "stateMutability": "view",
#         "type": "function"
#     },
#     {
#         "anonymous": False,
#         "inputs": [
#             {"indexed": True, "name": "agentId", "type": "bytes32"},
#             {"indexed": True, "name": "actionType", "type": "bytes32"},
#             {"indexed": False, "name": "permitted", "type": "bool"},
#             {"indexed": False, "name": "requestHash", "type": "bytes32"},
#             {"indexed": False, "name": "timestamp", "type": "uint256"},
#             {"indexed": False, "name": "caller", "type": "address"}
#         ],
#         "name": "DecisionLogged",
#         "type": "event"
#     }
# ]


# # ══════════════════════════════════════════════════════════════════════════════
# # Data classes
# # ══════════════════════════════════════════════════════════════════════════════

# class PolicyMode(Enum):
#     BASELINE    = "A - Baseline (No Restrictions)"
#     CENTRALIZED = "B - Centralized JSON Policy"
#     BLOCKCHAIN  = "C - Blockchain Smart Contract"


# @dataclass
# class PolicyDecision:
#     agent_id:       str
#     action_type:    str
#     permitted:      bool
#     mode:           str
#     latency_ms:     float
#     timestamp:      str
#     request_hash:   str
#     tx_hash:        Optional[str] = None
#     block_number:   Optional[int] = None
#     gas_used:       Optional[int] = None
#     reason:         str = ""
#     error:          Optional[str] = None

#     def to_dict(self):
#         return asdict(self)


# # ══════════════════════════════════════════════════════════════════════════════
# # SQLite audit store (used for System B and as local mirror for System C)
# # ══════════════════════════════════════════════════════════════════════════════

# class AuditStore:
#     def __init__(self, db_path: str = "/tmp/agent_audit.db"):
#         self.db_path = db_path
#         self._lock = threading.Lock()
#         self._init_db()

#     def _init_db(self):
#         with sqlite3.connect(self.db_path) as conn:
#             conn.execute("""
#                 CREATE TABLE IF NOT EXISTS decisions (
#                     id INTEGER PRIMARY KEY AUTOINCREMENT,
#                     agent_id TEXT,
#                     action_type TEXT,
#                     permitted INTEGER,
#                     mode TEXT,
#                     latency_ms REAL,
#                     timestamp TEXT,
#                     request_hash TEXT,
#                     tx_hash TEXT,
#                     block_number INTEGER,
#                     gas_used INTEGER,
#                     reason TEXT,
#                     error TEXT
#                 )
#             """)
#             conn.commit()

#     def log(self, decision: PolicyDecision):
#         with self._lock:
#             with sqlite3.connect(self.db_path) as conn:
#                 conn.execute("""
#                     INSERT INTO decisions
#                     (agent_id, action_type, permitted, mode, latency_ms, timestamp,
#                      request_hash, tx_hash, block_number, gas_used, reason, error)
#                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
#                 """, (
#                     decision.agent_id, decision.action_type,
#                     int(decision.permitted), decision.mode,
#                     decision.latency_ms, decision.timestamp,
#                     decision.request_hash, decision.tx_hash,
#                     decision.block_number, decision.gas_used,
#                     decision.reason, decision.error
#                 ))
#                 conn.commit()

#     def get_all(self) -> list[dict]:
#         with sqlite3.connect(self.db_path) as conn:
#             conn.row_factory = sqlite3.Row
#             rows = conn.execute(
#                 "SELECT * FROM decisions ORDER BY id DESC LIMIT 200"
#             ).fetchall()
#             return [dict(r) for r in rows]

#     def get_stats(self) -> dict:
#         with sqlite3.connect(self.db_path) as conn:
#             row = conn.execute("""
#                 SELECT
#                   COUNT(*) as total,
#                   SUM(CASE WHEN permitted=1 THEN 1 ELSE 0 END) as allowed,
#                   SUM(CASE WHEN permitted=0 THEN 1 ELSE 0 END) as denied,
#                   AVG(latency_ms) as avg_latency,
#                   MIN(latency_ms) as min_latency,
#                   MAX(latency_ms) as max_latency
#                 FROM decisions
#             """).fetchone()
#             return dict(row) if row else {}


# # ══════════════════════════════════════════════════════════════════════════════
# # Policy Engine
# # ══════════════════════════════════════════════════════════════════════════════

# class PolicyEngine:
#     """
#     Core policy engine supporting three modes:
#     A) Baseline: no restrictions
#     B) Centralized: Python dict / JSON file
#     C) Blockchain: Solidity smart contract via web3.py
#     """

#     def __init__(
#         self,
#         mode: PolicyMode = PolicyMode.BLOCKCHAIN,
#         ganache_url: str = "http://127.0.0.1:8545",
#         contract_address: Optional[str] = None,
#         deployer_private_key: Optional[str] = None,
#         policy_file: Optional[str] = None,
#     ):
#         self.mode = mode
#         self.audit = AuditStore()
#         self._centralized_policy = dict(DEFAULT_CENTRALIZED_POLICY)
        
#         # Blockchain state
#         self.w3 = None
#         self.contract = None
#         self.deployer_account = None
#         self._blockchain_ready = False
#         self._nonce = 0
#         self._nonce_lock = threading.Lock()  # Thread-safe nonce management

#         # Load custom JSON policy if provided
#         if policy_file and os.path.exists(policy_file):
#             with open(policy_file) as f:
#                 self._centralized_policy = json.load(f)

#         # Web3 setup (only for blockchain mode)
#         if mode == PolicyMode.BLOCKCHAIN and WEB3_AVAILABLE:
#             self._init_blockchain(ganache_url, contract_address, deployer_private_key)

#     # ── Blockchain initialization ──────────────────────────────────────────────

#     def _init_blockchain(self, ganache_url, contract_address, deployer_private_key):
#         try:
#             self.w3 = Web3(Web3.HTTPProvider(ganache_url, request_kwargs={"timeout": 10}))
#             self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

#             if not self.w3.is_connected():
#                 print(f"[PolicyEngine] ERROR: Cannot connect to {ganache_url}")
#                 return

#             # Use first account if no key provided
#             if deployer_private_key:
#                 self.deployer_account = self.w3.eth.account.from_key(deployer_private_key)
#             else:
#                 self.deployer_account = self.w3.eth.accounts[0]

#             if contract_address:
#                 self.contract = self.w3.eth.contract(
#                     address=Web3.to_checksum_address(contract_address),
#                     abi=CONTRACT_ABI
#                 )
#                 self._blockchain_ready = True
#                 self._nonce = self.w3.eth.get_transaction_count(
#                     self.deployer_account.address if hasattr(self.deployer_account, 'address') 
#                     else self.deployer_account
#                 )
#                 print(f"[PolicyEngine] ✓ Connected to contract at {contract_address}")
#                 print(f"[PolicyEngine] ✓ Deployer: {self.deployer_account.address if hasattr(self.deployer_account, 'address') else self.deployer_account}")
#                 print(f"[PolicyEngine] ✓ Initial nonce: {self._nonce}")
                
#                 # Initialize default permissions
#                 self._init_default_permissions()
#             else:
#                 print("[PolicyEngine] ERROR: No contract address provided")

#         except Exception as e:
#             print(f"[PolicyEngine] Blockchain init error: {e}")
#             import traceback
#             traceback.print_exc()

#     def _init_default_permissions(self):
#         """Set default permissions for test agents on-chain."""
#         if not self._blockchain_ready:
#             return
        
#         DEFAULT_PERMISSIONS = {
#             "agent_a": {"search_web": True, "read_file": True, "transfer_money": False, "execute_command": False, "delete_database": False},
#             "agent_b": {"search_web": True, "read_file": True, "transfer_money": True, "execute_command": False, "delete_database": False},
#             "agent_c": {"search_web": True, "read_file": False, "transfer_money": False, "execute_command": False, "delete_database": False},
#         }
        
#         print("[PolicyEngine] Initializing default permissions on-chain...")
#         for agent_id, permissions in DEFAULT_PERMISSIONS.items():
#             try:
#                 agent_bytes = self._to_bytes32(agent_id)
#                 for action, permitted in permissions.items():
#                     action_bytes = self._to_bytes32(action)
#                     acct = self.deployer_account.address if hasattr(self.deployer_account, 'address') else self.deployer_account
                    
#                     with self._nonce_lock:
#                         current_nonce = self._nonce
                        
#                         tx = self.contract.functions.setPermission(
#                             agent_bytes, action_bytes, permitted
#                         ).build_transaction({
#                             "from": acct,
#                             "nonce": current_nonce,
#                             "gas": 100_000,
#                             "gasPrice": self.w3.to_wei("20", "gwei"),
#                         })
                    
#                     signed = self.w3.eth.account.sign_transaction(tx, self.deployer_account.key)
#                     tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
                    
#                     # Wait with timeout
#                     try:
#                         receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
#                         print(f"  ✓ {agent_id}/{action}={permitted}")
#                         with self._nonce_lock:
#                             latest_nonce = self.w3.eth.get_transaction_count(acct, block_identifier='pending')
#                             self._nonce = max(self._nonce + 1, latest_nonce)
#                     except Exception as wait_err:
#                         print(f"  ✗ {agent_id}/{action}: timeout {wait_err}")
#                         with self._nonce_lock:
#                             self._nonce += 1
                        
#             except Exception as e:
#                 print(f"  ✗ {agent_id}: {e}")

#     def deploy_contract(self, bytecode: str) -> str:
#         """Deploy the contract and return its address."""
#         if not self.w3 or not self.w3.is_connected():
#             raise RuntimeError("Web3 not connected")

#         Contract = self.w3.eth.contract(abi=CONTRACT_ABI, bytecode=bytecode)
#         tx = Contract.constructor().build_transaction({
#             "from": self.deployer_account if isinstance(self.deployer_account, str)
#                     else self.deployer_account.address,
#             "nonce": self.w3.eth.get_transaction_count(
#                 self.deployer_account if isinstance(self.deployer_account, str)
#                 else self.deployer_account.address
#             ),
#             "gas": 3_000_000,
#             "gasPrice": self.w3.to_wei("20", "gwei"),
#         })
#         signed = self.w3.eth.account.sign_transaction(tx, self.deployer_account.key)
#         tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
#         receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
#         self.contract = self.w3.eth.contract(
#             address=receipt.contractAddress, abi=CONTRACT_ABI
#         )
#         self._blockchain_ready = True
#         return receipt.contractAddress

#     # ── Permission management ──────────────────────────────────────────────────

#     def set_agent_permissions(self, agent_id: str, permissions: dict[str, bool]):
#         """
#         Configure permissions for an agent.
#         For blockchain mode: writes to smart contract.
#         For centralized mode: updates in-memory dict.
#         """
#         if self.mode == PolicyMode.BLOCKCHAIN and self._blockchain_ready:
#             agent_bytes = self._to_bytes32(agent_id)
#             acct = self.deployer_account.address if hasattr(self.deployer_account, 'address') else self.deployer_account
            
#             for action, permitted in permissions.items():
#                 action_bytes = self._to_bytes32(action)
#                 try:
#                     with self._nonce_lock:
#                         current_nonce = self._nonce
                        
#                         tx = self.contract.functions.setPermission(
#                             agent_bytes, action_bytes, permitted
#                         ).build_transaction({
#                             "from": acct,
#                             "nonce": current_nonce,
#                             "gas": 100_000,
#                             "gasPrice": self.w3.to_wei("20", "gwei"),
#                         })
                        
#                         signed = self.w3.eth.account.sign_transaction(tx, self.deployer_account.key)
#                         tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
#                         print(f"[Chain] setPermission tx sent: {tx_hash.hex()[:12]}... (nonce={current_nonce})")
                    
#                     try:
#                         receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=10)
#                         print(f"[Chain] ✓ setPermission confirmed for {agent_id}/{action}")
#                         with self._nonce_lock:
#                             latest_nonce = self.w3.eth.get_transaction_count(acct, block_identifier='pending')
#                             self._nonce = max(self._nonce + 1, latest_nonce)
#                     except Exception as wait_err:
#                         print(f"[Chain] ✗ setPermission timeout: {wait_err}")
#                         with self._nonce_lock:
#                             self._nonce += 1
                            
#                 except Exception as e:
#                     print(f"[Chain] ✗ setPermission error for {agent_id}/{action}: {e}")
#                     import traceback
#                     traceback.print_exc()
#         else:
#             self._centralized_policy[agent_id] = permissions

#     # ── Core decision method ───────────────────────────────────────────────────

#     def check_permission(
#         self,
#         agent_id: str,
#         action_type: str,
#         request_payload: str = ""
#     ) -> PolicyDecision:
#         """
#         The main entry point. Returns a PolicyDecision with full metadata.
#         """
#         start = time.perf_counter()
#         action_lower = action_type.lower()
#         timestamp = datetime.utcnow().isoformat() + "Z"
#         request_hash = self._compute_hash(agent_id, action_lower, timestamp, request_payload)

#         permitted = False
#         tx_hash = None
#         block_number = None
#         gas_used = None
#         reason = ""
#         error = None

#         try:
#             if self.mode == PolicyMode.BASELINE:
#                 permitted = True
#                 reason = "Baseline mode: all actions permitted"

#             elif self.mode == PolicyMode.CENTRALIZED:
#                 agent_policy = self._centralized_policy.get(agent_id, {})
#                 permitted = agent_policy.get(action_lower, False)
#                 reason = f"Centralized policy: {'ALLOW' if permitted else 'DENY'}"

#             elif self.mode == PolicyMode.BLOCKCHAIN:
#                 if self._blockchain_ready:
#                     agent_bytes  = self._to_bytes32(agent_id)
#                     action_bytes = self._to_bytes32(action_lower)
#                     acct = self.deployer_account.address if hasattr(self.deployer_account, 'address') else self.deployer_account
                    
#                     try:
#                         # View call - read permission
#                         permitted = self.contract.functions.checkPermission(
#                             agent_bytes, action_bytes
#                         ).call()
#                         reason = f"Smart contract: {'✓ ALLOW' if permitted else '✗ DENY'}"
                        
#                         # Log decision as on-chain transaction
#                         try:
#                             hash_bytes = bytes.fromhex(request_hash if len(request_hash) == 64 else 
#                                                       request_hash.replace('0x', ''))
                            
#                             with self._nonce_lock:
#                                 current_nonce = self._nonce
                                
#                                 tx = self.contract.functions.logDecision(
#                                     agent_bytes, action_bytes, permitted, hash_bytes
#                                 ).build_transaction({
#                                     "from": acct,
#                                     "nonce": current_nonce,
#                                     "gas": 80_000,
#                                     "gasPrice": self.w3.to_wei("20", "gwei"),
#                                 })
                                
#                                 signed = self.w3.eth.account.sign_transaction(
#                                     tx, self.deployer_account.key
#                                 )
#                                 raw_tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
#                                 print(f"[Chain] Sent tx {raw_tx_hash.hex()[:12]}... (nonce={current_nonce})")
                            
#                             # Wait for confirmation with timeout
#                             try:
#                                 receipt = self.w3.eth.wait_for_transaction_receipt(raw_tx_hash, timeout=10)
#                                 tx_hash = receipt.transactionHash.hex()
#                                 block_number = receipt.blockNumber
#                                 gas_used = receipt.gasUsed
                                
#                                 with self._nonce_lock:
#                                     # Refresh nonce from latest block
#                                     latest_nonce = self.w3.eth.get_transaction_count(acct, block_identifier='pending')
#                                     self._nonce = max(self._nonce + 1, latest_nonce)
                                
#                                 print(f"[Chain] ✓ {agent_id}/{action_lower} confirmed at block #{block_number} | tx={tx_hash[:16]}... | gas={gas_used}")
                                
#                             except Exception as wait_err:
#                                 print(f"[Chain] ✗ Wait timeout: {type(wait_err).__name__}: {wait_err}")
#                                 with self._nonce_lock:
#                                     self._nonce += 1
                                
#                         except Exception as log_err:
#                             error = f"Log tx failed: {log_err}"
#                             print(f"[Chain] ✗ {error}")
#                             import traceback
#                             traceback.print_exc()
                            
#                     except Exception as check_err:
#                         error = f"Check failed: {check_err}"
#                         permitted = False
#                         reason = f"Contract error: {check_err}"
#                         print(f"[Chain] Error checking permission: {check_err}")
#                 else:
#                     # Fallback to centralized if blockchain unavailable
#                     agent_policy = self._centralized_policy.get(agent_id, {})
#                     permitted = agent_policy.get(action_lower, False)
#                     reason = "Blockchain unavailable — centralized fallback"
#                     print(f"[PolicyEngine] Blockchain not ready, using fallback")

#         except Exception as e:
#             error = str(e)
#             permitted = False
#             reason = f"Error: {e} — defaulting DENY"

#         latency_ms = (time.perf_counter() - start) * 1000

#         decision = PolicyDecision(
#             agent_id=agent_id,
#             action_type=action_lower,
#             permitted=permitted,
#             mode=self.mode.value,
#             latency_ms=round(latency_ms, 2),
#             timestamp=timestamp,
#             request_hash=request_hash,
#             tx_hash=tx_hash,
#             block_number=block_number,
#             gas_used=gas_used,
#             reason=reason,
#             error=error,
#         )
#         self.audit.log(decision)
#         return decision

#     # ── Helpers ────────────────────────────────────────────────────────────────

#     @staticmethod
#     def _to_bytes32(s: str) -> bytes:
#         encoded = s.encode("utf-8")[:32]
#         return encoded.ljust(32, b"\x00")

#     @staticmethod
#     # def _compute_hash(agent_id, action, timestamp, payload) -> str:
#     #     raw = f"{agent_id}:{action}:{timestamp}:{payload}"
#     #     return hashlib.keccak_256(raw.encode()).hexdigest()
#     @staticmethod
#     def _compute_hash(agent_id, action, timestamp, payload) -> str:
#         raw = f"{agent_id}:{action}:{timestamp}:{payload}".encode()
#         if HAS_KECCAK:
#             return keccak(raw).hex()
#         else:
#             return hashlib.sha256(raw).hexdigest()

#     def get_audit_log(self) -> list[dict]:
#         return self.audit.get_all()

#     def get_stats(self) -> dict:
#         return self.audit.get_stats()

#     def get_blockchain_stats(self) -> Optional[dict]:
#         if self._blockchain_ready:
#             try:
#                 decisions, denials = self.contract.functions.getStats().call()
#                 return {"on_chain_decisions": decisions, "on_chain_denials": denials}
#             except Exception:
#                 pass
#         return None
"""
policy_engine.py  —  BlockGuard
Blockchain-based policy enforcement for autonomous AI agents.

Three modes:
  A) Baseline    — no check, all permitted
  B) Centralized — Python dict
  C) Blockchain  — Solidity smart contract via web3.py on Ganache
"""

import time
import json
import hashlib
import sqlite3
import os
import queue
import random
import tempfile
import threading
from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime

# ── keccak hash ────────────────────────────────────────────────────────────────
try:
    from eth_hash.auto import keccak
    HAS_KECCAK = True
except ImportError:
    HAS_KECCAK = False

# ── web3 ───────────────────────────────────────────────────────────────────────
try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

# ── geth_poa_middleware — optional, API changed across web3 versions ───────────
_poa_mw = None
try:
    from web3.middleware import geth_poa_middleware          # web3 < 7
    _poa_mw = geth_poa_middleware
except ImportError:
    try:
        from web3.middleware import ExtraDataToPOAMiddleware # web3 >= 7
        _poa_mw = ExtraDataToPOAMiddleware
    except ImportError:
        pass   # Ganache works fine without it

# ══════════════════════════════════════════════════════════════════════════════
# ABI
# ══════════════════════════════════════════════════════════════════════════════

CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "agentId",    "type": "bytes32"},
            {"internalType": "bytes32", "name": "actionType", "type": "bytes32"},
            {"internalType": "bool",    "name": "permitted",  "type": "bool"}
        ],
        "name": "setPermission", "outputs": [],
        "stateMutability": "nonpayable", "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "agentId",    "type": "bytes32"},
            {"internalType": "bytes32", "name": "actionType", "type": "bytes32"}
        ],
        "name": "checkPermission",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "view", "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "agentId",     "type": "bytes32"},
            {"internalType": "bytes32", "name": "actionType",  "type": "bytes32"},
            {"internalType": "bool",    "name": "permitted",   "type": "bool"},
            {"internalType": "bytes32", "name": "requestHash", "type": "bytes32"}
        ],
        "name": "logDecision", "outputs": [],
        "stateMutability": "nonpayable", "type": "function"
    },
    {
        "inputs": [],
        "name": "getStats",
        "outputs": [
            {"internalType": "uint256", "name": "decisions", "type": "uint256"},
            {"internalType": "uint256", "name": "denials",   "type": "uint256"}
        ],
        "stateMutability": "view", "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view", "type": "function"
    }
]

# ══════════════════════════════════════════════════════════════════════════════
# Default policy (centralized fallback / mode B)
# ══════════════════════════════════════════════════════════════════════════════

DEFAULT_CENTRALIZED_POLICY = {
    "agent_a": {
        "search_web": True,  "read_file": True,
        "transfer_money": False, "execute_command": False, "delete_database": False,
    },
    "agent_b": {
        "search_web": True,  "read_file": True,
        "transfer_money": True, "execute_command": False, "delete_database": False,
    },
    "agent_c": {
        "search_web": True,  "read_file": False,
        "transfer_money": False, "execute_command": False, "delete_database": False,
    },
}

# ══════════════════════════════════════════════════════════════════════════════
# Enums / data classes
# ══════════════════════════════════════════════════════════════════════════════

class PolicyMode(Enum):
    BASELINE    = "A - Baseline (No Restrictions)"
    CENTRALIZED = "B - Centralized JSON Policy"
    BLOCKCHAIN  = "C - Blockchain Smart Contract"


@dataclass
class PolicyDecision:
    agent_id:     str
    action_type:  str
    permitted:    bool
    mode:         str
    latency_ms:   float
    timestamp:    str
    request_hash: str
    tx_hash:      Optional[str] = None
    block_number: Optional[int] = None
    gas_used:     Optional[int] = None
    reason:       str = ""
    error:        Optional[str] = None

    def to_dict(self):
        return asdict(self)

# ══════════════════════════════════════════════════════════════════════════════
# SQLite audit store
# ══════════════════════════════════════════════════════════════════════════════

class AuditStore:
    DEFAULT_DB = os.path.join(
        os.getenv("BLOCKGUARD_DATA_DIR") or tempfile.gettempdir(), "agent_audit.db")

    def __init__(self, db_path: str = None):
        db_path = db_path or AuditStore.DEFAULT_DB
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT, action_type TEXT, permitted INTEGER,
                    mode TEXT, latency_ms REAL, timestamp TEXT,
                    request_hash TEXT, tx_hash TEXT, block_number INTEGER,
                    gas_used INTEGER, reason TEXT, error TEXT
                )
            """)
            c.commit()

    def log(self, d: PolicyDecision):
        with self._lock:
            with sqlite3.connect(self.db_path) as c:
                c.execute("""
                    INSERT INTO decisions
                    (agent_id,action_type,permitted,mode,latency_ms,timestamp,
                     request_hash,tx_hash,block_number,gas_used,reason,error)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                """, (d.agent_id, d.action_type, int(d.permitted), d.mode,
                      d.latency_ms, d.timestamp, d.request_hash, d.tx_hash,
                      d.block_number, d.gas_used, d.reason, d.error))
                c.commit()

    def get_all(self):
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute(
                "SELECT * FROM decisions ORDER BY id DESC LIMIT 200"
            ).fetchall()]

    def get_stats(self):
        with sqlite3.connect(self.db_path) as c:
            r = c.execute("""
                SELECT COUNT(*) as total,
                  SUM(CASE WHEN permitted=1 THEN 1 ELSE 0 END) as allowed,
                  SUM(CASE WHEN permitted=0 THEN 1 ELSE 0 END) as denied,
                  AVG(latency_ms) as avg_latency
                FROM decisions
            """).fetchone()
            return dict(r) if r else {}

# ══════════════════════════════════════════════════════════════════════════════
# Policy Engine
# ══════════════════════════════════════════════════════════════════════════════

class PolicyEngine:

    def __init__(
        self,
        mode: PolicyMode              = PolicyMode.BLOCKCHAIN,
        ganache_url: str              = "http://127.0.0.1:8545",
        contract_address: Optional[str] = None,
        deployer_private_key: Optional[str] = None,
    ):
        self.mode  = mode
        self.audit = AuditStore()
        self._centralized_policy = {
            k: dict(v) for k, v in DEFAULT_CENTRALIZED_POLICY.items()
        }

        # Blockchain state
        # Optionally move the audit write off the enforcement path.
        # Optionally inject read faults to measure the availability cost of failing closed.
        self.async_audit  = os.getenv("BLOCKGUARD_ASYNC_AUDIT", "0") == "1"
        self.fault_rate   = float(os.getenv("BLOCKGUARD_FAULT_RATE", "0") or 0)
        self._audit_q     = queue.Queue()
        self._audit_worker = None
        self.audit_lag_ms = []
        self.fault_count  = 0

        self.w3               = None
        self.contract         = None
        self.deployer_account = None
        self._blockchain_ready = False
        self._tx_lock          = threading.Lock()   # one tx at a time

        if mode == PolicyMode.BLOCKCHAIN and WEB3_AVAILABLE:
            self._init_blockchain(ganache_url, contract_address, deployer_private_key)

    # ── init ──────────────────────────────────────────────────────────────────

    def _init_blockchain(self, url, contract_address, private_key):
        try:
            self.w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 15}))

            # inject PoA middleware if available (harmless on Ganache either way)
            if _poa_mw is not None:
                try:
                    self.w3.middleware_onion.inject(_poa_mw, layer=0)
                except Exception:
                    pass

            if not self.w3.is_connected():
                print(f"[PolicyEngine] ✗ Cannot connect to {url}")
                return

            # Resolve deployer — MUST have private key to sign transactions
            if private_key:
                self.deployer_account = self.w3.eth.account.from_key(private_key)
                print(f"[PolicyEngine] ✓ Deployer: {self.deployer_account.address}")
            else:
                print("[PolicyEngine] ✗ No DEPLOYER_PRIVATE_KEY set — cannot sign transactions")
                print("[PolicyEngine]   Set it in app.py or as env var DEPLOYER_PRIVATE_KEY")
                print("[PolicyEngine]   Hardhat/Ganache default key: "
                      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                return

            if not contract_address:
                print("[PolicyEngine] ✗ No contract address — run: npx hardhat run scripts/deploy.js --network ganache")
                return

            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=CONTRACT_ABI
            )

            # Quick sanity check — call a view function
            owner = self.contract.functions.owner().call()
            print(f"[PolicyEngine] ✓ Contract at {contract_address}")
            print(f"[PolicyEngine] ✓ Contract owner: {owner}")
            print(f"[PolicyEngine] ✓ Block number: {self.w3.eth.block_number}")

            self._blockchain_ready = True

        except Exception as e:
            print(f"[PolicyEngine] ✗ Init error: {e}")
            import traceback; traceback.print_exc()

    # ── nonce — always read fresh from chain, never track internally ──────────

    def _ensure_audit_worker(self):
        if self._audit_worker and self._audit_worker.is_alive():
            return
        def drain():
            while True:
                fn, queued_at = self._audit_q.get()
                try:
                    self._send_tx(fn, gas=80_000)
                    self.audit_lag_ms.append((time.time() - queued_at) * 1000)
                except Exception as e:
                    print(f"[PolicyEngine] async audit write failed: {e}")
                finally:
                    self._audit_q.task_done()
        self._audit_worker = threading.Thread(target=drain, daemon=True)
        self._audit_worker.start()

    def audit_backlog(self) -> int:
        """Decisions executed but not yet recorded on-chain (the asynchronous-audit safety window)."""
        return self._audit_q.qsize()

    def _get_nonce(self) -> int:
        """Always read the pending nonce fresh from Ganache. Never cache."""
        addr = self.deployer_account.address
        return self.w3.eth.get_transaction_count(addr, block_identifier="pending")

    # ── send a signed transaction ─────────────────────────────────────────────

    def _send_tx(self, fn, gas: int = 80_000) -> Optional[dict]:
        """
        Build → sign → send → wait for receipt.
        Uses a lock so concurrent requests don't produce nonce collisions.
        Returns the receipt dict or None on failure.
        """
        if not self._blockchain_ready:
            return None
        addr = self.deployer_account.address
        with self._tx_lock:
            try:
                nonce = self._get_nonce()
                tx = fn.build_transaction({
                    "from":     addr,
                    "nonce":    nonce,
                    "gas":      gas,
                    "gasPrice": self.w3.to_wei("20", "gwei"),
                })
                signed  = self.w3.eth.account.sign_transaction(tx, self.deployer_account.key)
                # web3.py >= 7 exposes .raw_transaction; 5.x/6.x use .rawTransaction
                raw_bytes = getattr(signed, "raw_transaction", None)
                if raw_bytes is None:
                    raw_bytes = signed.rawTransaction
                raw     = self.w3.eth.send_raw_transaction(raw_bytes)
                receipt = self.w3.eth.wait_for_transaction_receipt(raw, timeout=30)
                print(f"[Chain] ✓ tx={receipt.transactionHash.hex()[:18]}… "
                      f"block=#{receipt.blockNumber} gas={receipt.gasUsed}")
                return receipt
            except Exception as e:
                print(f"[Chain] ✗ tx failed: {e}")
                return None

    # ── public: set permission ────────────────────────────────────────────────

    def set_agent_permissions(self, agent_id: str, permissions: dict):
        if self.mode == PolicyMode.BLOCKCHAIN and self._blockchain_ready:
            for action, permitted in permissions.items():
                ab = self._to_bytes32(agent_id)
                ac = self._to_bytes32(action)
                fn = self.contract.functions.setPermission(ab, ac, permitted)
                receipt = self._send_tx(fn, gas=100_000)
                if receipt:
                    print(f"[Chain] setPermission({agent_id}, {action}, {permitted}) "
                          f"→ block #{receipt.blockNumber}")
        else:
            self._centralized_policy.setdefault(agent_id, {}).update(permissions)

    # ── core: check permission ────────────────────────────────────────────────

    def check_permission(
        self,
        agent_id:        str,
        action_type:     str,
        request_payload: str = "",
    ) -> PolicyDecision:

        t0           = time.perf_counter()
        action_lower = action_type.lower()
        ts           = datetime.utcnow().isoformat() + "Z"
        req_hash     = self._compute_hash(agent_id, action_lower, ts, request_payload)

        permitted    = False
        tx_hash      = None
        block_number = None
        gas_used     = None
        reason       = ""
        error        = None

        try:
            if self.mode == PolicyMode.BASELINE:
                permitted = True
                reason    = "Baseline: all actions permitted"

            elif self.mode == PolicyMode.CENTRALIZED:
                permitted = self._centralized_policy.get(agent_id, {}).get(action_lower, False)
                reason    = f"Centralized policy: {'ALLOW' if permitted else 'DENY'}"

            elif self.mode == PolicyMode.BLOCKCHAIN:
                if not self._blockchain_ready:
                    # graceful fallback
                    permitted = self._centralized_policy.get(agent_id, {}).get(action_lower, False)
                    reason    = "Blockchain unavailable — centralized fallback"
                else:
                    ab = self._to_bytes32(agent_id)
                    ac = self._to_bytes32(action_lower)

                    # 1. View call — free, no gas, no tx
                    if self.fault_rate and random.random() < self.fault_rate:
                        self.fault_count += 1
                        raise ConnectionError("injected RPC fault (BLOCKGUARD_FAULT_RATE)")
                    permitted = self.contract.functions.checkPermission(ab, ac).call()
                    reason    = f"Smart contract: {'✓ ALLOW' if permitted else '✗ DENY'}"

                    # 2. Log decision on-chain (write tx)
                    hash_bytes = bytes.fromhex(req_hash)
                    fn      = self.contract.functions.logDecision(ab, ac, permitted, hash_bytes)
                    if self.async_audit:
                        # Asynchronous audit: write off the enforcement path. The decision
                        # returns immediately; the record lands later.
                        self._ensure_audit_worker()
                        self._audit_q.put((fn, time.time()))
                        reason += " (audit queued)"
                    else:
                        receipt = self._send_tx(fn, gas=80_000)
                        if receipt:
                            tx_hash      = receipt.transactionHash.hex()
                            block_number = receipt.blockNumber
                            gas_used     = receipt.gasUsed

        except Exception as e:
            error     = str(e)
            permitted = False
            reason    = f"Error — defaulting DENY: {e}"
            print(f"[PolicyEngine] ✗ check_permission error: {e}")
            import traceback; traceback.print_exc()

        decision = PolicyDecision(
            agent_id=agent_id, action_type=action_lower,
            permitted=permitted, mode=self.mode.value,
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
            timestamp=ts, request_hash=req_hash,
            tx_hash=tx_hash, block_number=block_number,
            gas_used=gas_used, reason=reason, error=error,
        )
        self.audit.log(decision)
        return decision

    # ── helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _to_bytes32(s: str) -> bytes:
        return s.encode("utf-8")[:32].ljust(32, b"\x00")

    @staticmethod
    def _compute_hash(agent_id, action, timestamp, payload) -> str:
        raw = f"{agent_id}:{action}:{timestamp}:{payload}".encode()
        if HAS_KECCAK:
            return keccak(raw).hex()
        return hashlib.sha256(raw).hexdigest()

    def get_audit_log(self):
        return self.audit.get_all()

    def get_stats(self):
        return self.audit.get_stats()

    def get_blockchain_stats(self):
        if not self._blockchain_ready:
            return None
        try:
            d, dn = self.contract.functions.getStats().call()
            return {"on_chain_decisions": d, "on_chain_denials": dn}
        except Exception:
            return None