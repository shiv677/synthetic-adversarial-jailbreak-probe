import argparse
import json
import sys
from pathlib import Path
from typing import List

try:
    from .models import MutationStrategy, ProbeItem, RefusalMetrics
    from .probe import SimulatedGuardrailModel, run_adversarial_audit
except ImportError:
    from models import MutationStrategy, ProbeItem, RefusalMetrics
    from probe import SimulatedGuardrailModel, run_adversarial_audit


def run_cli_audit(data_path: Path, mode: str = "standard") -> RefusalMetrics:
    if not data_path.exists():
        print(f"Error: Dataset not found at {data_path}", file=sys.stderr)
        sys.exit(1)

    with open(data_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    probes = [ProbeItem(**item) for item in data.get("probes", [])]
    strategies = [
        MutationStrategy.NONE,
        MutationStrategy.BASE64,
        MutationStrategy.CIPHER_ROT13,
        MutationStrategy.PREFIX_INJECTION,
        MutationStrategy.LEETSPEAK,
    ]

    model = SimulatedGuardrailModel(mode=mode)
    metrics = run_adversarial_audit(probes, strategies, target_fn=model.generate)

    print("=" * 80)
    print("Synthetic Adversarial Jailbreak & Guardrail Safety Audit")
    print("=" * 80)
    print(f"Dataset:              {data_path.name}")
    print(f"Guardrail Mode:       {mode.upper()}")
    print(f"Total Probes Run:     {metrics.total_probes}")
    print(f"Harmful Probes:       {metrics.harmful_probes} | Benign Probes: {metrics.benign_probes}")
    print(f"Safe Refusals:        {metrics.safe_refusals}")
    print(f"Unsafe Bypasses:      {metrics.unsafe_bypasses}")
    print(f"False Positives:      {metrics.false_positive_refusals}")
    print(f"System Leaks:         {metrics.system_leaks}")
    print("-" * 80)
    print(f"Refusal Accuracy:     {metrics.refusal_accuracy * 100:.1f}%")
    print(f"Attack Success Rate:  {metrics.attack_success_rate * 100:.1f}%")
    print(f"False Positive Rate:  {metrics.false_positive_rate * 100:.1f}%")
    print("=" * 80)

    return metrics


def main():
    default_dataset = Path(__file__).parent / "sample_adversarial_dataset.json"
    parser = argparse.ArgumentParser(description="Audit LLM guardrails against adversarial mutations.")
    parser.add_argument("--data", type=Path, default=default_dataset, help="Path to probe JSON dataset.")
    parser.add_argument("--mode", type=str, default="standard", choices=["standard", "naive", "leaky", "strict"])
    args = parser.parse_args()

    run_cli_audit(args.data, mode=args.mode)


if __name__ == "__main__":
    main()
