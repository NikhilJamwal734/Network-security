
"""
API-008.4 / API-008.5
Firewall Configuration Analyzer Performance Benchmark

Measures the FastAPI analysis endpoint using an
in-process test client.

Usage:
    python -m scripts.benchmark_analysis --runs 20
"""

import argparse
import math
import statistics
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.api.main import app


def analyze_once(client, filename, content):
    start = time.perf_counter()

    response = client.post(
        "/api/v1/analyze",
        files={
            "file": (
                filename,
                content,
                "text/plain",
            )
        },
    )

    elapsed_ms = (
        time.perf_counter() - start
    ) * 1000

    if response.status_code != 200:
        raise RuntimeError(
            f"Analysis failed: HTTP {response.status_code}\n"
            f"{response.text[:500]}"
        )

    return elapsed_ms, response.json()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark firewall analysis."
    )

    parser.add_argument(
        "--file",
        default="configs/firewall.conf",
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=20,
    )

    args = parser.parse_args()

    if not 2 <= args.runs <= 1000:
        parser.error(
            "--runs must be between 2 and 1000"
        )

    config_path = Path(args.file)

    if not config_path.is_file():
        parser.error(
            f"File not found: {config_path}"
        )

    content = config_path.read_bytes()
    timings = []

    print("=" * 55)
    print("FIREWALL ANALYZER PERFORMANCE BENCHMARK")
    print("=" * 55)
    print(f"Configuration: {config_path}")
    print(f"File size: {len(content):,} bytes")
    print(f"Measured runs: {args.runs}")
    print()

    with TestClient(app) as client:
        # Warm-up analysis
        _, baseline = analyze_once(
            client,
            config_path.name,
            content,
        )

        expected = (
            baseline["hostname"],
            baseline["summary"],
            baseline["configuration"],
            baseline["findings"],
        )

        for index in range(args.runs):
            elapsed, data = analyze_once(
                client,
                config_path.name,
                content,
            )

            actual = (
                data["hostname"],
                data["summary"],
                data["configuration"],
                data["findings"],
            )

            if actual != expected:
                raise RuntimeError(
                    "Report changed between benchmark runs."
                )

            timings.append(elapsed)

            print(
                f"Run {index + 1:02d}: "
                f"{elapsed:.2f} ms"
            )

    ordered = sorted(timings)
    p95_index = math.ceil(
        0.95 * len(ordered)
    ) - 1

    print()
    print("=" * 55)
    print("PERFORMANCE SUMMARY")
    print("=" * 55)

    print(
        f"Average: {statistics.mean(timings):.2f} ms"
    )
    print(
        f"Median:  {statistics.median(timings):.2f} ms"
    )
    print(
        f"P95:     {ordered[p95_index]:.2f} ms"
    )
    print(
        f"Fastest: {min(timings):.2f} ms"
    )
    print(
        f"Slowest: {max(timings):.2f} ms"
    )

    print()
    print("REPORT VERIFICATION")
    print(f"Hostname: {baseline['hostname']}")
    print(
        "Security score: "
        f"{baseline['summary']['security_score']}/100"
    )
    print(
        "Total findings: "
        f"{baseline['summary']['total_findings']}"
    )

    print()
    print("Benchmark completed successfully.")


if __name__ == "__main__":
    main()
