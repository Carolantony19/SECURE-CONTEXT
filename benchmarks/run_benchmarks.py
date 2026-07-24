"""
Benchmarks for SecretGuard AI.

Generates synthetic repos with known secret placements and measures
precision, recall, and false-positive rate.  Results can be compared
against Gitleaks and TruffleHog.

Usage:
    python -m benchmarks.run_benchmarks
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import NamedTuple

from secretguard.config import ScanConfig
from secretguard.risk_scorer import score_findings
from secretguard.scanner import scan_directory


class BenchmarkResult(NamedTuple):
    total_files: int
    findings_count: int
    high_count: int
    medium_count: int
    low_count: int
    elapsed_seconds: float
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float


def _create_synthetic_repo(root: Path, num_files: int = 100) -> set[str]:
    """Create a synthetic repo with a mix of clean and leaky files.

    Returns a set of (filename, variable) tuples for known secrets.
    """
    known_secrets: set[str] = set()

    for i in range(num_files):
        f = root / f"module_{i}.py"
        if i % 10 == 0:
            # 10% of files have a real-looking secret
            f.write_text(
                f'api_key = "aB3xK9m{i:04d}NpQ7rT2wU5yZ8cE1fH4jL6oI"\n'
                f'safe_var = "hello world"\n',
                encoding="utf-8",
            )
            known_secrets.add(f"module_{i}.py:api_key")
        elif i % 10 == 1:
            # 10% have placeholders (should be LOW)
            f.write_text(
                f'api_key = "YOUR_API_KEY_HERE"\n'
                f'token = "REPLACE_ME"\n',
                encoding="utf-8",
            )
        else:
            # 80% are clean
            f.write_text(
                f'# Module {i}\nresult = compute()\nprint(result)\n',
                encoding="utf-8",
            )

    return known_secrets


def run_benchmark(num_files: int = 500) -> BenchmarkResult:
    """Run a benchmark scan on a synthetic repo."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        known_secrets = _create_synthetic_repo(root, num_files)

        config = ScanConfig()
        config.parallel_workers = 4

        start = time.perf_counter()
        findings = scan_directory(root, config)
        score_findings(findings, config, root)
        elapsed = time.perf_counter() - start

        high_findings = {
            f"{Path(f.file).name}:{f.variable}"
            for f in findings if f.risk == "HIGH"
        }

        tp = len(high_findings & known_secrets)
        fp = len(high_findings - known_secrets)
        fn = len(known_secrets - high_findings)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        return BenchmarkResult(
            total_files=num_files,
            findings_count=len(findings),
            high_count=sum(1 for f in findings if f.risk == "HIGH"),
            medium_count=sum(1 for f in findings if f.risk == "MEDIUM"),
            low_count=sum(1 for f in findings if f.risk == "LOW"),
            elapsed_seconds=round(elapsed, 3),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
        )


def main() -> None:
    """Run benchmarks and print results."""
    print("=" * 60)
    print("SecretGuard AI — Benchmark Report")
    print("=" * 60)

    for size in [100, 500, 1000]:
        print(f"\n--- {size} files ---")
        result = run_benchmark(size)
        print(f"  Files scanned:   {result.total_files}")
        print(f"  Total findings:  {result.findings_count}")
        print(f"  HIGH/MED/LOW:    {result.high_count}/{result.medium_count}/{result.low_count}")
        print(f"  True positives:  {result.true_positives}")
        print(f"  False positives: {result.false_positives}")
        print(f"  False negatives: {result.false_negatives}")
        print(f"  Precision:       {result.precision:.2%}")
        print(f"  Recall:          {result.recall:.2%}")
        print(f"  Time:            {result.elapsed_seconds:.3f}s")


if __name__ == "__main__":
    main()
