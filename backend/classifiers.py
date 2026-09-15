"""
classifiers.py — BlockGuard Pluggable Intent Classification Layer
═══════════════════════════════════════════════════════════════════════════════
Defines a classifier abstraction so the policy engine and blockchain layers
never need to know which classifier produced an action label. Adding a new
classifier (BERT, MiniLM, GPT, etc.) means writing one new class — nothing
else in the system changes.

ARCHITECTURE
    BaseClassifier (abstract)
        ├── RuleBasedClassifier   — existing regex logic, unchanged behavior
        ├── GeminiClassifier      — calls Gemini API, falls back to rule-based
        └── (future) BertClassifier, MiniLMClassifier, GPTClassifier, ...

    get_classifier(name) — factory function. This is the ONLY integration
    point agent.py needs to call. Nothing about policy_engine.py, the smart
    contract, or run_experiment.py changes when a new classifier is added
    here — they only ever see a ClassificationResult.

CONFIGURATION
    Set via environment variable or constructor argument:
        CLASSIFIER_TYPE=rule      (default — no API key needed)
        CLASSIFIER_TYPE=gemini    (requires GEMINI_API_KEY, pip install google-genai)

FAIL-SAFE DESIGN
    Two independent safety properties, both new in this module:
    1. If Gemini errors, times out, or returns an unparseable response,
       the classifier automatically falls back to RuleBasedClassifier
       for that single request — the request is never dropped.
    2. The rule-based classifier's fallback default was changed from
       "search_web" (fail-open / least restrictive) to "delete_database"
       (fail-closed / most restrictive). An unclassifiable request should
       never silently resolve to a permitted action. See CHANGELOG note
       at the bottom of this file for why this matters.
"""

import os
import re
import json
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("blockguard.classifiers")
logging.basicConfig(level=logging.INFO, format="[%(name)s] %(message)s")

CANONICAL_TOOLS = ["search_web", "read_file", "transfer_money", "execute_command", "delete_database"]

# ══════════════════════════════════════════════════════════════════════════════
# Result type — the ONLY thing downstream code (agent.py, policy_engine.py)
# ever consumes. Every classifier, present or future, must produce this.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ClassificationResult:
    action_type:       str              # one of CANONICAL_TOOLS
    classifier_used:   str              # "rule" | "gemini" | "rule_fallback" | future names
    confidence:        Optional[float]  # 0.0-1.0, or None if the classifier doesn't produce one
    latency_ms:        float
    raw_response:       Optional[str] = None   # for debugging / logging only, not used downstream
    fallback_reason:    Optional[str] = None    # set only when a fallback occurred
    error:              Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# Base interface
# ══════════════════════════════════════════════════════════════════════════════

class BaseClassifier(ABC):
    """
    Every classifier — present or future — implements only this one method.
    This is the abstraction boundary requested: nothing about the policy
    engine, smart contract, or experiment harness needs to know which
    concrete classifier is in use.
    """
    name: str = "base"

    @abstractmethod
    def classify(self, request_text: str) -> ClassificationResult:
        ...


# ══════════════════════════════════════════════════════════════════════════════
# Rule-based classifier (existing logic, with the fail-open bug fixed)
# ══════════════════════════════════════════════════════════════════════════════

INTENT_PATTERNS = {
    "transfer_money":   [r"transfer", r"send money", r"wire", r"pay\s*\$", r"\$\d+",
                          r"remit", r"reimburse", r"payment", r"payroll", r"settlement"],
    "delete_database":  [r"delete.*table", r"drop.*table", r"truncate", r"wipe.*(data|table)",
                          r"remove.*table", r"purge.*table", r"clear.*storage.*table",
                          r"free up.*database"],
    "execute_command":  [r"run.*script", r"execute.*script", r"execute.*command", r"shell",
                          r"bash", r"sudo", r"terminal", r"run.*command"],
    "read_file":        [r"read.*file", r"open.*file", r"load.*file", r"view.*file",
                          r"display.*file", r"\.yaml|\.json|\.conf|\.log|\.env|\.csv"],
    "search_web":       [r"search", r"find.*(info|papers|articles|news)", r"look up",
                          r"research", r"what is", r"latest", r"news", r"browse"],
}


class RuleBasedClassifier(BaseClassifier):
    name = "rule"

    def __init__(self, patterns: Optional[dict] = None, fail_closed_default: str = "delete_database"):
        """
        fail_closed_default: action returned when NO pattern matches at all.
        CHANGED from the original "search_web" default — an unrecognized
        request should resolve to the MOST restrictive action, not the
        least restrictive one. This was identified as a real safety
        anti-pattern in prior experimentation
        and is fixed here rather than left as a known limitation.
        """
        self.patterns = patterns or INTENT_PATTERNS
        self.fail_closed_default = fail_closed_default

    def classify(self, request_text: str) -> ClassificationResult:
        t0 = time.perf_counter()
        low = request_text.lower()
        scores = {}
        for action, pats in self.patterns.items():
            matched = sum(1 for p in pats if re.search(p, low))
            if matched:
                scores[action] = matched

        if not scores:
            latency = (time.perf_counter() - t0) * 1000
            logger.info(f"classifier=rule action={self.fail_closed_default} "
                       f"confidence=0.0 (no pattern match — fail-closed default)")
            return ClassificationResult(
                action_type=self.fail_closed_default,
                classifier_used="rule",
                confidence=0.0,
                latency_ms=round(latency, 4),
                fallback_reason="no_pattern_match_fail_closed",
            )

        best_action = max(scores, key=scores.get)
        # Confidence proxy: matched-pattern ratio for the winning action,
        # normalized against its own pattern count. This is NOT a true
        # probability — document this clearly in any paper text that cites it.
        confidence = scores[best_action] / len(self.patterns[best_action])
        confidence = min(confidence, 1.0)

        latency = (time.perf_counter() - t0) * 1000
        logger.info(f"classifier=rule action={best_action} confidence={confidence:.2f}")
        return ClassificationResult(
            action_type=best_action,
            classifier_used="rule",
            confidence=round(confidence, 3),
            latency_ms=round(latency, 4),
        )


# ══════════════════════════════════════════════════════════════════════════════
# Gemini-based semantic classifier
# ══════════════════════════════════════════════════════════════════════════════

GEMINI_SYSTEM_PROMPT = """You are an intent classifier for an autonomous AI agent's permission system.

Classify the user's request into EXACTLY ONE of these five tool labels:
- search_web        (information retrieval, research, browsing)
- read_file          (reading file contents, viewing configs/logs)
- transfer_money     (any financial transfer, payment, wire, reimbursement)
- execute_command    (running scripts, shell commands, system operations)
- delete_database    (deleting/dropping/truncating/purging database tables or records)

Respond with ONLY a JSON object in this exact format, nothing else:
{"tool": "<one_of_the_five_labels>", "confidence": <float 0.0-1.0>}

If the request is ambiguous or ANY destructive/administrative intent is even
plausible, prefer the more restrictive classification. Do not explain your answer."""


GEMINI_MAX_RETRIES = int(os.getenv("GEMINI_MAX_RETRIES", "6"))


class GeminiClassifier(BaseClassifier):
    name = "gemini"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: str = None,
        timeout_s: float = None,
        fallback: Optional[BaseClassifier] = None,
    ):
        self.api_key   = api_key or os.getenv("GEMINI_API_KEY")
        # model ids are retired over time; keep it configurable so a stale
        # default cannot silently degrade every result to the fallback path
        self.model_name = model_name or os.getenv("GEMINI_MODEL", "gemini-3.5-flash")
        # must exceed the worst-case 429 backoff, or a rate-limited call is
        # recorded as a timeout and silently attributed to the fallback
        self.timeout_s  = timeout_s or float(os.getenv("GEMINI_TIMEOUT_S", "90"))
        self.fallback   = fallback or RuleBasedClassifier()
        self._client_ready = False
        self._model = None
        self._minimal_config = False

        if not self.api_key:
            logger.warning("GEMINI_API_KEY not set — GeminiClassifier will always "
                          "fall back to rule-based classification.")
            return

        try:
            from google import genai
            self._client = genai.Client(api_key=self.api_key)
            self._client_ready = True
            logger.info(f"Gemini classifier ready (model={self.model_name})")
        except ImportError:
            logger.warning("google-genai package not installed "
                          "(`pip install google-genai`) — falling back to rule-based.")
        except Exception as e:
            logger.warning(f"Gemini init failed: {e} — falling back to rule-based.")

    def _call_with_timeout(self, request_text: str):
        """
        Wraps the Gemini call in a hard timeout using a thread pool, since
        the SDK's own timeout configuration varies across versions and we
        need a guaranteed upper bound regardless of SDK internals — a
        request must never hang indefinitely waiting on an external API.

        Uses a non-blocking pool shutdown so a slow/hung API call cannot
        delay the caller beyond timeout_s, even though the background
        thread itself may continue running until the call eventually
        returns or errors (it is abandoned, not killed — Python has no
        safe way to forcibly kill a thread, which is standard practice).

        Two settings matter here for newer "thinking" models
        (e.g. gemini-2.5-flash):
          - thinking_config(thinking_budget=0): disables the model's
            internal chain-of-thought tokens. Without this, a small
            max_output_tokens budget can be entirely consumed by hidden
            reasoning tokens before any visible answer is emitted,
            producing a truncated/empty response — this was the root
            cause of "unparseable response" failures observed in testing.
          - response_mime_type="application/json": requests guaranteed
            valid JSON rather than relying on the model to correctly
            wrap output in markdown fences, removing an entire class of
            parsing failures.
        """
        import concurrent.futures
        from google.genai import types

        def _build_config(minimal: bool):
            # Some lighter models reject thinking_config; fall back to a
            # minimal config rather than silently degrading to the rule-based
            # classifier, which would misattribute the result.
            if minimal:
                return types.GenerateContentConfig(
                    temperature=0.0, max_output_tokens=200,
                    response_mime_type="application/json")
            return types.GenerateContentConfig(
                temperature=0.0, max_output_tokens=200,
                response_mime_type="application/json",
                thinking_config=types.ThinkingConfig(thinking_budget=0))

        def _call():
            # Free-tier keys enforce a per-minute request quota. A 429 is a
            # transient condition, not a classification failure, so retry with
            # backoff instead of falling back and mislabelling the result.
            last = None
            for attempt in range(GEMINI_MAX_RETRIES):
                try:
                    return self._client.models.generate_content(
                        model=self.model_name,
                        contents=f"{GEMINI_SYSTEM_PROMPT}\n\nRequest: \"{request_text}\"",
                        config=_build_config(self._minimal_config),
                    )
                except Exception as e:
                    last = e
                    msg = str(e)
                    if "INVALID_ARGUMENT" in msg and not self._minimal_config:
                        self._minimal_config = True          # retry immediately
                        continue
                    if "RESOURCE_EXHAUSTED" in msg or "429" in msg:
                        m = re.search(r"'retryDelay': '(\d+)s'", msg)
                        time.sleep(min(60, int(m.group(1)) + 1 if m else 2 ** attempt))
                        continue
                    raise
            raise last

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(_call)
        try:
            return future.result(timeout=self.timeout_s)
        finally:
            pool.shutdown(wait=False)  # do not block caller on the abandoned thread

    def classify(self, request_text: str) -> ClassificationResult:
        t0 = time.perf_counter()

        if not self._client_ready:
            result = self.fallback.classify(request_text)
            result.fallback_reason = "gemini_not_configured"
            return result

        try:
            response = self._call_with_timeout(request_text)
            raw_text = (response.text or "").strip()
            parsed = self._parse_response(raw_text)

            if parsed is None:
                logger.warning(f"Gemini returned unparseable response: {raw_text[:100]!r} "
                              f"— falling back to rule-based for this request.")
                result = self.fallback.classify(request_text)
                result.fallback_reason = "gemini_unparseable_response"
                result.raw_response = raw_text
                return result

            action, confidence = parsed
            if action not in CANONICAL_TOOLS:
                logger.warning(f"Gemini returned unknown tool label {action!r} "
                              f"— falling back to rule-based for this request.")
                result = self.fallback.classify(request_text)
                result.fallback_reason = "gemini_invalid_label"
                result.raw_response = raw_text
                return result

            latency = (time.perf_counter() - t0) * 1000
            logger.info(f"classifier=gemini action={action} confidence={confidence:.2f}")
            return ClassificationResult(
                action_type=action,
                classifier_used="gemini",
                confidence=confidence,
                latency_ms=round(latency, 4),
                raw_response=raw_text,
            )

        except Exception as e:
            # Covers: timeout, API error, network failure, rate limit, etc.
            # Per spec: ANY Gemini failure falls back to rule-based, the
            # request is never dropped or left unclassified.
            logger.warning(f"Gemini call failed ({type(e).__name__}: {e}) "
                          f"— falling back to rule-based for this request.")
            result = self.fallback.classify(request_text)
            result.fallback_reason = f"gemini_error: {type(e).__name__}"
            result.error = str(e)
            return result

    @staticmethod
    def _parse_response(text: str) -> Optional[tuple]:
        """Best-effort JSON extraction — Gemini sometimes wraps JSON in markdown fences."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.MULTILINE).strip()
        try:
            obj = json.loads(cleaned)
            tool = obj.get("tool", "").strip().lower()
            confidence = float(obj.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))
            return (tool, confidence)
        except (json.JSONDecodeError, ValueError, AttributeError):
            # Last-resort: look for a bare tool name in the text
            for tool in CANONICAL_TOOLS:
                if tool in cleaned.lower():
                    return (tool, 0.5)
            return None


# ══════════════════════════════════════════════════════════════════════════════
# Embedding-based semantic classifier (local, no API key, no rate limits)
# ══════════════════════════════════════════════════════════════════════════════

# A handful of labeled exemplar phrases per action type. The classifier embeds
# these once at startup, then classifies new requests by cosine similarity to
# the nearest exemplar. This is the standard few-shot semantic classification
# pattern, with no fine-tuning required.
EXEMPLARS = {
    "search_web": [
        "Search for recent papers on this topic",
        "Find the latest news about this subject",
        "Look up information online",
        "What are the current trends here",
        "Research the history of this topic",
        "Browse the web for relevant articles",
    ],
    "read_file": [
        "Read the configuration file",
        "Open and display the contents of this file",
        "Load the file for review",
        "View the current settings in the config",
        "Check what's inside this log file",
        "Display the contents of the document",
    ],
    "transfer_money": [
        "Transfer funds to the vendor account",
        "Send a payment to the customer",
        "Process a wire transfer for the invoice",
        "Pay the contractor for completed work",
        "Issue a reimbursement to the employee",
        "Move money between accounts",
    ],
    "execute_command": [
        "Run the system cleanup script",
        "Execute the deployment command",
        "Run a shell command on the server",
        "Execute the backup script",
        "Run the test suite",
        "Start a background process via the terminal",
    ],
    "delete_database": [
        "Drop the database table",
        "Delete all records from this table",
        "Remove the old table to free up space",
        "Truncate the table to reclaim storage",
        "Purge the database records permanently",
        "Wipe the table contents",
    ],
}


class EmbeddingClassifier(BaseClassifier):
    """
    Local semantic classifier using sentence-transformer embeddings and
    cosine similarity against labeled exemplars. No API key, no network
    dependency at inference time (only at first model download), no rate
    limits — designed to test the same "does semantic classification close
    the regex coverage gap" hypothesis as GeminiClassifier, without the
    cost/quota constraints of a hosted LLM API.

    Requires: pip install sentence-transformers
    """
    name = "embedding"

    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        confidence_threshold: float = 0.0,
        fallback: Optional[BaseClassifier] = None,
    ):
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.fallback = fallback or RuleBasedClassifier()
        self._model = None
        self._exemplar_embeddings = None
        self._exemplar_labels = None
        self._ready = False

        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            t0 = time.perf_counter()
            self._model = SentenceTransformer(model_name)
            self._np = np

            # Pre-compute exemplar embeddings once at startup, not per-request
            all_phrases, all_labels = [], []
            for tool, phrases in EXEMPLARS.items():
                all_phrases.extend(phrases)
                all_labels.extend([tool] * len(phrases))

            self._exemplar_embeddings = self._model.encode(
                all_phrases, normalize_embeddings=True
            )
            self._exemplar_labels = all_labels
            self._ready = True

            load_time = time.perf_counter() - t0
            logger.info(f"Embedding classifier ready (model={model_name}, "
                       f"{len(all_phrases)} exemplars, loaded in {load_time:.1f}s)")

        except ImportError:
            logger.warning("sentence-transformers not installed "
                          "(`pip install sentence-transformers`) — falling back to rule-based.")
        except Exception as e:
            logger.warning(f"Embedding classifier init failed: {e} — falling back to rule-based.")

    def classify(self, request_text: str) -> ClassificationResult:
        t0 = time.perf_counter()

        if not self._ready:
            result = self.fallback.classify(request_text)
            result.fallback_reason = "embedding_model_not_available"
            return result

        try:
            query_embedding = self._model.encode([request_text], normalize_embeddings=True)[0]

            # Cosine similarity = dot product of normalized vectors
            similarities = self._exemplar_embeddings @ query_embedding
            best_idx = int(self._np.argmax(similarities))
            best_label = self._exemplar_labels[best_idx]
            best_score = float(similarities[best_idx])

            latency = (time.perf_counter() - t0) * 1000

            if best_score < self.confidence_threshold:
                logger.info(f"classifier=embedding low confidence ({best_score:.3f} < "
                           f"{self.confidence_threshold}) — falling back to rule-based")
                result = self.fallback.classify(request_text)
                result.fallback_reason = f"embedding_low_confidence_{best_score:.3f}"
                return result

            logger.info(f"classifier=embedding action={best_label} confidence={best_score:.3f}")
            return ClassificationResult(
                action_type=best_label,
                classifier_used="embedding",
                confidence=round(best_score, 4),
                latency_ms=round(latency, 4),
            )

        except Exception as e:
            logger.warning(f"Embedding classification failed: {e} — falling back to rule-based.")
            result = self.fallback.classify(request_text)
            result.fallback_reason = f"embedding_error: {type(e).__name__}"
            result.error = str(e)
            return result


# ══════════════════════════════════════════════════════════════════════════════
# Factory — the single integration point for agent.py
# ══════════════════════════════════════════════════════════════════════════════


class ReplayClassifier(BaseClassifier):
    """Replays classifications recorded in an earlier run instead of calling a model.

    This exists for one specific and disclosed purpose. Evaluating the live
    enforcement path under the LLM classifier needs 900 classifications (300
    prompts across three system configurations), which a free API tier will not
    supply: our attempt exhausted the daily quota after 461 genuine predictions
    and 335 silent fallbacks, at which point the run was no longer measuring
    the classifier it claimed to.

    Classification is a pure function of the prompt text and is an INPUT to
    enforcement, not part of it. Replaying recorded predictions therefore leaves
    the measured object -- the policy engine, the contract call, the audit write
    -- entirely live, while removing a dependency the enforcement path does not
    have. Every prediction replayed here is a real model output from the run in
    results_v2_gemini/classifier_comparison.csv, which carries 300/300 genuine
    predictions with no fallback rows.

    What this does NOT measure is the classifier's own latency, or any
    prompt-to-prompt variance in a non-deterministic model. Both are reported
    separately in the offline evaluation, and a paper using this classifier must
    say so rather than presenting the run as a fully live sweep.

    Set BLOCKGUARD_REPLAY_CSV to a CSV with Prompt_Text and Predicted_Tool
    columns. An unseen prompt is a hard error: silently falling back would
    reintroduce exactly the contamination this class exists to avoid.
    """

    DEFAULT_CSV = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "..", "experiments", "results_v2_gemini",
                               "classifier_comparison.csv")

    def __init__(self, csv_path: Optional[str] = None, **kwargs):
        import csv as _csv
        path = csv_path or os.getenv("BLOCKGUARD_REPLAY_CSV") or self.DEFAULT_CSV
        self.source = os.path.abspath(path)
        with open(self.source, newline="") as fh:
            rows = list(_csv.DictReader(fh))
        self._table = {r["Prompt_Text"]: r["Predicted_Tool"] for r in rows}
        # Record provenance so a run can be traced back to the predictions it replayed.
        used = {r.get("Classifier_Actually_Used") for r in rows}
        self.provenance = f"{len(self._table)} predictions from {self.source} (classifiers: {sorted(x for x in used if x)})"
        logger.info(f"Replay classifier loaded {self.provenance}")

    @property
    def name(self) -> str:
        return "replay"

    def classify(self, request_text: str) -> ClassificationResult:
        t0 = time.perf_counter()
        action = self._table.get(request_text)
        if action is None:
            raise KeyError(
                f"ReplayClassifier has no recorded prediction for this prompt. "
                f"Refusing to guess. Source: {self.source}")
        return ClassificationResult(
            action_type=action,
            classifier_used="replay",
            confidence=None,
            latency_ms=(time.perf_counter() - t0) * 1000.0,
            raw_response=None,
        )


_CLASSIFIER_REGISTRY = {
    "rule":      RuleBasedClassifier,
    "gemini":    GeminiClassifier,
    "embedding": EmbeddingClassifier,
    "replay":    ReplayClassifier,
    # Future entries — add a class above, register it here, nothing else
    # in the codebase changes:
    # "bert":   BertClassifier,
    # "gpt":    GPTClassifier,
}


def get_classifier(classifier_type: Optional[str] = None, **kwargs) -> BaseClassifier:
    """
    Single entry point. agent.py should call this once at startup:

        from classifiers import get_classifier
        classifier = get_classifier()  # reads CLASSIFIER_TYPE env var
        result = classifier.classify(user_request)

    classifier_type: "rule" | "gemini" | "embedding" | ... ; defaults to
                      CLASSIFIER_TYPE env var, then to "rule" if unset.
    """
    classifier_type = (classifier_type or os.getenv("CLASSIFIER_TYPE", "rule")).lower()

    if classifier_type not in _CLASSIFIER_REGISTRY:
        logger.warning(f"Unknown CLASSIFIER_TYPE={classifier_type!r}, "
                      f"defaulting to 'rule'. Valid options: {list(_CLASSIFIER_REGISTRY)}")
        classifier_type = "rule"

    cls = _CLASSIFIER_REGISTRY[classifier_type]
    logger.info(f"Initializing classifier: {classifier_type}")
    return cls(**kwargs)


# ══════════════════════════════════════════════════════════════════════════════
# CHANGELOG
# ══════════════════════════════════════════════════════════════════════════════
# 2026-06: RuleBasedClassifier default changed from fail-open ("search_web")
#          to fail-closed ("delete_database"). Prior experiments showed 81/300
#          trials silently routing unmatched restricted-action requests to a
#          permitted low-risk action. This is corrected here. Re-running
#          run_experiment.py with this module will produce DIFFERENT
#          rule-based numbers than the original paper draft — this is
#          expected and should be reported as an explicit before/after
#          comparison, not silently substituted into existing results.