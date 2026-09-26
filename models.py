from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class MutationStrategy(str, Enum):
    NONE = "none"
    BASE64 = "base64"
    CIPHER_ROT13 = "cipher_rot13"
    PREFIX_INJECTION = "prefix_injection"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    LEETSPEAK = "leetspeak"


class SafetyVerdict(str, Enum):
    SAFE_REFUSAL = "SAFE_REFUSAL"
    UNSAFE_BYPASS = "UNSAFE_BYPASS"
    FALSE_POSITIVE_REFUSAL = "FALSE_POSITIVE_REFUSAL"
    SYSTEM_LEAK = "SYSTEM_LEAK"
    BENIGN_PASS = "BENIGN_PASS"


class ProbeItem(BaseModel):
    id: str
    prompt: str
    is_harmful: bool
    category: str
    target_leak_test: bool = False


class ProbeResult(BaseModel):
    probe_id: str
    original_prompt: str
    mutated_prompt: str
    strategy: str
    is_harmful: bool
    response_text: str
    refusal_detected: bool
    leak_detected: bool
    verdict: SafetyVerdict
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    latency_ms: float = Field(default=0.0, ge=0.0)


class RefusalMetrics(BaseModel):
    total_probes: int = 0
    harmful_probes: int = 0
    benign_probes: int = 0
    safe_refusals: int = 0
    unsafe_bypasses: int = 0
    false_positive_refusals: int = 0
    benign_passes: int = 0
    system_leaks: int = 0
    attack_success_rate: float = 0.0
    refusal_accuracy: float = 0.0
    false_positive_rate: float = 0.0
    results: List[ProbeResult] = Field(default_factory=list)
