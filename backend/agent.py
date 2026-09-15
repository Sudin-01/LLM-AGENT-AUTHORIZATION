"""
backend/agent.py
Autonomous AI Agent with blockchain-enforced permission layer.

Mode A — Baseline:    no policy, executes everything
Mode B — Centralized: Python dict policy
Mode C — Blockchain:  smart contract via web3.py
"""

import time, re, os
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class AgentMode(Enum):
    BASELINE    = "A"
    CENTRALIZED = "B"
    BLOCKCHAIN  = "C"


TOOLS = {
    "search_web":       {"risk": "low",      "description": "Search the web for information"},
    "read_file":        {"risk": "medium",   "description": "Read a file from the filesystem"},
    "transfer_money":   {"risk": "high",     "description": "Transfer funds to an account"},
    "execute_command":  {"risk": "high",     "description": "Execute a shell command"},
    "delete_database":  {"risk": "critical", "description": "Delete a database table"},
}

INTENT_PATTERNS = {
    "transfer_money":   [r"transfer", r"send money", r"wire", r"pay\s*\$", r"\$\d+", r"remit"],
    "delete_database":  [r"delete.*database", r"drop\s+table", r"truncate", r"wipe.*data", r"remove.*records"],
    "execute_command":  [r"run.*script", r"execute.*command", r"shell", r"bash", r"sudo", r"terminal"],
    "read_file":        [r"read.*file", r"open.*file", r"load.*file", r"view.*file", r"\.yaml|\.json|\.conf|\.log"],
    "search_web":       [r"search", r"find.*info", r"look up", r"research", r"what is", r"latest", r"news"],
}


@dataclass
class AgentStep:
    step_num: int
    description: str
    action_type: Optional[str] = None
    permitted: Optional[bool] = None
    policy_latency_ms: Optional[float] = None
    output: Optional[str] = None


@dataclass
class AgentResult:
    request:           str
    agent_id:          str
    mode:              str
    classified_action: str
    permitted:         bool
    reasoning:         str
    steps:             list = field(default_factory=list)
    output:            Optional[str] = None
    blocked_reason:    Optional[str] = None
    total_latency_ms:  float = 0.0
    policy_latency_ms: float = 0.0
    tx_hash:           Optional[str] = None
    block_number:      Optional[int] = None
    gas_used:          Optional[int] = None
    timestamp:         str = ""

    def to_dict(self):
        return asdict(self)


# class IntentClassifier:
#     def classify(self, request: str) -> str:
#         low = request.lower()
#         scores = {}
#         for action, patterns in INTENT_PATTERNS.items():
#             s = sum(1 for p in patterns if re.search(p, low))
#             if s:
#                 scores[action] = s
#         return max(scores, key=scores.get) if scores else "search_web"
from classifiers import get_classifier

class IntentClassifier:
    def __init__(self):
        self._clf = get_classifier()  # reads CLASSIFIER_TYPE env var

    def classify(self, request: str) -> str:
        result = self._clf.classify(request)
        return result.action_type


class AgentRunner:
    def __init__(
        self,
        mode: AgentMode = AgentMode.BLOCKCHAIN,
        policy_engine=None,
        agent_id: str = "agent_a",
        openai_api_key: Optional[str] = None,
        openai_model: str = "gpt-4o-mini",
    ):
        self.mode          = mode
        self.policy_engine = policy_engine
        self.agent_id      = agent_id
        self.classifier    = IntentClassifier()
        self.openai_client = None
        self.openai_model  = openai_model

        if openai_api_key and OPENAI_AVAILABLE:
            try:
                import httpx
                self.openai_client = OpenAI(
                    api_key=openai_api_key,
                    http_client=httpx.Client()
                )
            except Exception:
                try:
                    self.openai_client = OpenAI(api_key=openai_api_key)
                except Exception:
                    self.openai_client = None

    def run(self, request: str, agent_id: Optional[str] = None) -> AgentResult:
        t0       = time.perf_counter()
        agent_id = agent_id or self.agent_id
        steps    = []
        ts       = datetime.utcnow().isoformat() + "Z"

        # Step 1: classify
        steps.append(AgentStep(1, "Classifying intent"))
        action = self.classifier.classify(request)
        steps[-1].action_type = action
        steps[-1].output = f"Classified as: {action} (risk: {TOOLS[action]['risk']})"

        # Step 2: policy check
        steps.append(AgentStep(2, f"Policy check — mode {self.mode.value}"))
        t_pol = time.perf_counter()
        permitted, tx_hash, block_number, gas_used = self._check_policy(agent_id, action, request)
        pol_ms = (time.perf_counter() - t_pol) * 1000
        steps[-1].permitted        = permitted
        steps[-1].policy_latency_ms = round(pol_ms, 2)
        steps[-1].output = f"{'ALLOW' if permitted else 'DENY'} in {pol_ms:.1f}ms" + (f" | tx={tx_hash}" if tx_hash else "")

        # Step 3: execute or block
        output         = None
        blocked_reason = None
        steps.append(AgentStep(3, "Executing" if permitted else "Blocking"))

        if permitted:
            output = self._execute(action, request)
            steps[-1].output = output
        else:
            blocked_reason = (
                f"Action '{action}' is DENIED for {agent_id}. "
                + ("Decision recorded on-chain." if self.mode == AgentMode.BLOCKCHAIN
                   else "Blocked by centralized policy.")
            )
            steps[-1].output = f"BLOCKED: {blocked_reason}"

        reasoning = self._reasoning(request, action, permitted)

        return AgentResult(
            request=request, agent_id=agent_id, mode=self.mode.value,
            classified_action=action, permitted=permitted, reasoning=reasoning,
            steps=steps, output=output, blocked_reason=blocked_reason,
            total_latency_ms=round((time.perf_counter() - t0) * 1000, 2),
            policy_latency_ms=round(pol_ms, 2),
            tx_hash=tx_hash, block_number=block_number, gas_used=gas_used,
            timestamp=ts,
        )

    def _check_policy(self, agent_id, action, request):
        tx_hash = block_number = gas_used = None
        if self.policy_engine is not None:
            d = self.policy_engine.check_permission(agent_id, action, request)
            return d.permitted, d.tx_hash, d.block_number, d.gas_used
        # standalone fallback
        if self.mode == AgentMode.BASELINE:
            return True, None, None, None
        defaults = {
            "agent_b": {"search_web": True, "read_file": True,
                        "transfer_money": True, "execute_command": False, "delete_database": False},
            "agent_c": {"search_web": True, "read_file": False,
                        "transfer_money": False, "execute_command": False, "delete_database": False},
        }
        p = defaults.get(agent_id, {a: False for a in TOOLS})
        return p.get(action, False), None, None, None

    def _execute(self, action: str, request: str) -> str:
        """
        For search_web: call OpenAI to get a real answer.
        For all others: simulate the action output.
        """
        if action == "search_web" and self.openai_client:
            try:
                resp = self.openai_client.chat.completions.create(
                    model=self.openai_model,
                    max_tokens=400,
                    messages=[
                        {"role": "system", "content": (
                            "You are a helpful web search assistant. "
                            "Answer the user's query concisely and informatively "
                            "as if you searched the web. Include key facts, "
                            "recent developments, and relevant details. "
                            "Format with short paragraphs."
                        )},
                        {"role": "user", "content": request},
                    ]
                )
                return resp.choices[0].message.content
            except Exception as e:
                return f"[search_web] OpenAI error: {e}"

        # Simulated outputs for non-search actions
        simulated = {
            "read_file":       "File contents retrieved:\n---\nconfig:\n  env: production\n  version: 2.1.4\n  db_host: localhost:5432\n---",
            "transfer_money":  "Wire transfer initiated.\nAmount: as requested\nDestination: VENDOR-ACC-9821\nStatus: Pending confirmation",
            "execute_command": "Command executed successfully.\nExit code: 0\nOutput: Process completed.",
            "delete_database": "Table dropped successfully.\nRows deleted: 14,392\nStorage freed: 2.3 GB",
        }
        return simulated.get(action, f"[{action}] Action executed.")

    def _reasoning(self, request: str, action: str, permitted: bool) -> str:
        if self.openai_client:
            try:
                resp = self.openai_client.chat.completions.create(
                    model=self.openai_model,
                    max_tokens=200,
                    messages=[
                        {"role": "system", "content": (
                            "You are an autonomous AI agent reasoning about an action request. "
                            f"The action was classified as '{action}' (risk: {TOOLS[action]['risk']}). "
                            f"The policy decision was: {'PERMITTED' if permitted else 'DENIED'}. "
                            "Explain your reasoning in 2-3 sentences."
                        )},
                        {"role": "user", "content": request},
                    ]
                )
                return resp.choices[0].message.content
            except Exception:
                pass
        # fallback
        risk = TOOLS[action]["risk"]
        if permitted:
            return f"Request classified as '{action}' ({risk} risk). Policy check passed — proceeding with execution."
        return f"Request classified as '{action}' ({risk} risk). Policy enforcement blocked this action — insufficient permissions for this agent."