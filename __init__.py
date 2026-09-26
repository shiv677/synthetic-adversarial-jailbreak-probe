"""Synthetic Adversarial Jailbreak Probe & Red-Teaming Safety Evaluator.

Generates adversarial perturbations (Base64, ROT13 cipher, prefix injection,
hypothetical framing, leetspeak) to audit LLM guardrail robustness, refusal
accuracy, false positive refusal rates, and system prompt leak resistance.
"""

from .models import MutationStrategy, ProbeItem, ProbeResult, RefusalMetrics, SafetyVerdict
from .probe import (
    SimulatedGuardrailModel,
    apply_mutation,
    detect_refusal,
    detect_system_leak,
    run_adversarial_audit,
)

__all__ = [
    "MutationStrategy",
    "ProbeItem",
    "ProbeResult",
    "RefusalMetrics",
    "SafetyVerdict",
    "SimulatedGuardrailModel",
    "apply_mutation",
    "detect_refusal",
    "detect_system_leak",
    "run_adversarial_audit",
]
