"""Re-export of the production classifier module (backend/classifiers.py).

This file used to be a *copy*. The two drifted: the copy kept a hardcoded
``gemini-1.5-flash`` default after the production module had been made
configurable, so an entire 300-prompt Gemini run silently fell back to the
rule-based classifier and produced plausible-looking results that were not
Gemini's. Loading the production module by path removes that failure mode
permanently. The previous copy is preserved in git history.
"""
import importlib.util
import os
import sys

_BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "backend", "classifiers.py")
_spec = importlib.util.spec_from_file_location("blockguard_classifiers", _BACKEND)
_mod = importlib.util.module_from_spec(_spec)
sys.modules["blockguard_classifiers"] = _mod
_spec.loader.exec_module(_mod)

BaseClassifier      = _mod.BaseClassifier
RuleBasedClassifier = _mod.RuleBasedClassifier
GeminiClassifier    = _mod.GeminiClassifier
EmbeddingClassifier = _mod.EmbeddingClassifier
ClassificationResult = _mod.ClassificationResult
CANONICAL_TOOLS     = _mod.CANONICAL_TOOLS
get_classifier      = _mod.get_classifier
