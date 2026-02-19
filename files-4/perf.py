"""
benchmark/perf.py
=================
Performance benchmark suite for HyPQ-Mess hybrid KEM primitives.

Measures and compares:
    1. Key generation    : X25519 vs. Kyber-768 vs. Hybrid
    2. Encapsulation     : Kyber-768 vs. X25519 ECDH
    3. Session key derivation: HKDF overhead
    4. Encryption        : AES-256-GCM at 1KB / 10KB / 100KB
    5. Full handshake    : End-to-end classical vs. hybrid latency

Outputs:
    - Console table (Rich)
    - JSON export: benchmark/results.json
    - Matplotlib plots: benchmark/latency_comparison.png

Usage:
    python -m hy_pq_mess.benchmark.perf
    python -m hy_pq_mess.benchmark.perf --iterations 200 --export

Author : HyPQ-Mess Research Team
License: MIT
"""

from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False
    class Console:
        def print(self, *args, **kwargs): print(*[str(a) for a in args])
        def rule(self, *args, **kwargs): print("=" * 60)
    class Table:
        def __init__(self, *args, **kwargs): self._rows = []; self._cols = []
        def add_column(self, name, **kw): self._cols.append(name)
        def add_row(self, *args): self._rows.append(args)
        def __repr__(self):
            lines = [" | ".join(self._cols)]
            lines += [" | ".join(str(c) for c in r) for r in self._rows]
            return "\n".join(lines)

from ..crypto.hybrid_kem import HybridKEM, HybridPublicBundle
from ..crypto.primitives import (
    AESGCMEncryptor,
    hkdf_derive,
    secure_random_bytes,
)

console = Console()

BENCHMARK_DIR = os.path.dirname(__file__)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class BenchResult:
    """Statistical summary of a benchmark run."""
    name: str
    iterations: int
    mean_us: float
    median_us: float
    stdev_us: float
    min_us: float
    max_us: float
    throughput_ops_sec: float = 0.0
    notes: str = ""

    @classmethod
    def from_timings(cls, name: str, timings_us: List[float], notes: str = "") -> "BenchResult":
        return cls(
            name=name,
            iterations=len(timings_us),
            mean_us=statistics.mean(timings_us),
            median_us=statistics.median(timings_us),
            stdev_us=statistics.stdev(timings_us) if len(timings_us) > 1 else 0.0,
            min_us=min(timings_us),
            max_us=max(timings_us),
            throughput_ops_sec=1_000_000 / statistics.mean(timings_us),
            notes=notes,
        )


# ---------------------------------------------------------------------------
# Timer utility
# ---------------------------------------------------------------------------

def time_function(fn: Callable, n: int = 100) -> List[float]:
    """
    Time `fn()` for `n` iterations.

    Returns:
        List of execution times in microseconds.
    """
    timings = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        t1 = time.perf_counter_ns()
        timings.append((t1 - t0) / 1_000)  # nanoseconds → microseconds
    return timings


# ---------------------------------------------------------------------------
# Individual benchmarks
# ---------------------------------------------------------------------------

def bench_x25519_keygen(n: int = 100) -> BenchResult:
    """Benchmark X25519 ephemeral key generation."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    timings = time_function(X25519PrivateKey.generate, n)
    return BenchResult.from_timings("X25519 KeyGen", timings, notes="Classical ECDH keygen")


def bench_x25519_ecdh(n: int = 100) -> BenchResult:
    """Benchmark X25519 ECDH key exchange."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv_a = X25519PrivateKey.generate()
    priv_b = X25519PrivateKey.generate()
    pub_b = priv_b.public_key()
    timings = time_function(lambda: priv_a.exchange(pub_b), n)
    return BenchResult.from_timings("X25519 ECDH", timings, notes="Classical key exchange")


def bench_hybrid_keygen(n: int = 50) -> BenchResult:
    """Benchmark Hybrid KEM (X25519 + Kyber-768) key generation."""
    def _gen():
        kem = HybridKEM()
        kem.generate_keypair()
    timings = time_function(_gen, n)
    kem = HybridKEM()
    note = "REAL Kyber-768" if kem.using_real_kyber else "Kyber SIMULATION"
    return BenchResult.from_timings("Hybrid KeyGen", timings, notes=f"X25519 + {note}")


def bench_hybrid_encap_decap(n: int = 50) -> BenchResult:
    """Benchmark full Kyber-768 encapsulate + decapsulate cycle."""
    kem_a = HybridKEM()
    pub_a = kem_a.generate_keypair()
    kem_b = HybridKEM()
    pub_b = kem_b.generate_keypair()

    def _encap_decap():
        ct, encap = kem_b.encapsulate(pub_a)
        kem_a.decapsulate(ct, pub_b.x25519_pub)

    timings = time_function(_encap_decap, n)
    return BenchResult.from_timings("Hybrid Encap+Decap", timings, notes="Full KEM round-trip")


def bench_hkdf(n: int = 200) -> BenchResult:
    """Benchmark HKDF-SHA256 key derivation."""
    ikm = secure_random_bytes(64)
    salt = secure_random_bytes(32)
    timings = time_function(lambda: hkdf_derive(ikm, salt=salt), n)
    return BenchResult.from_timings("HKDF-SHA256", timings, notes="32-byte key derivation")


def bench_aesgcm_encrypt(payload_size: int = 1024, n: int = 200) -> BenchResult:
    """Benchmark AES-256-GCM encryption at given payload size."""
    key = secure_random_bytes(32)
    enc = AESGCMEncryptor(key)
    plaintext = secure_random_bytes(payload_size)
    timings = time_function(lambda: enc.encrypt(plaintext), n)
    throughput = (payload_size * len(timings)) / (sum(timings) / 1e6) / (1024 * 1024)
    result = BenchResult.from_timings(
        f"AES-256-GCM Enc ({payload_size//1024}KB)",
        timings,
        notes=f"{throughput:.1f} MB/s",
    )
    return result


def bench_full_handshake(n: int = 20) -> BenchResult:
    """
    Benchmark the full in-process hybrid handshake (no network I/O).

    Simulates all 3 handshake phases:
        ClientHello → ServerHello → ClientFinish
    """
    from ..protocol.handshake import ClientHandshake, ServerHandshake

    def _handshake():
        cli = ClientHandshake(client_id="benchclient")
        srv = ServerHandshake(server_id="benchserver")

        hello_raw = cli.create_client_hello()
        srv_hello_raw = srv.process_client_hello(hello_raw)
        finish_raw = cli.process_server_hello(srv_hello_raw)
        srv.process_client_finish(finish_raw)

    timings = time_function(_handshake, n)
    return BenchResult.from_timings(
        "Full Hybrid Handshake",
        timings,
        notes="3-msg: ClientHello→ServerHello→Finish (no network)",
    )


# ---------------------------------------------------------------------------
# Results printer
# ---------------------------------------------------------------------------

def print_results_table(results: List[BenchResult]) -> None:
    """Print benchmark results as a Rich formatted table."""
    table = Table(title="HyPQ-Mess Performance Benchmarks", show_lines=True)
    table.add_column("Operation", style="bold cyan", min_width=28)
    table.add_column("Iterations", justify="right")
    table.add_column("Mean (µs)", justify="right", style="green")
    table.add_column("Median (µs)", justify="right")
    table.add_column("Stdev (µs)", justify="right")
    table.add_column("Min (µs)", justify="right")
    table.add_column("Max (µs)", justify="right")
    table.add_column("Ops/sec", justify="right", style="yellow")
    table.add_column("Notes", style="dim")

    for r in results:
        table.add_row(
            r.name,
            str(r.iterations),
            f"{r.mean_us:.1f}",
            f"{r.median_us:.1f}",
            f"{r.stdev_us:.1f}",
            f"{r.min_us:.1f}",
            f"{r.max_us:.1f}",
            f"{r.throughput_ops_sec:,.0f}",
            r.notes,
        )

    console.print(table)


def export_results(results: List[BenchResult], path: str) -> None:
    """Export benchmark results as JSON."""
    data = [asdict(r) for r in results]
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[dim]Results exported to {path}[/dim]")


def plot_results(results: List[BenchResult], path: str) -> None:
    """Generate latency comparison bar chart."""
    try:
        import matplotlib.pyplot as plt
        import numpy as np

        names = [r.name for r in results]
        means = [r.mean_us for r in results]
        stdevs = [r.stdev_us for r in results]

        x = np.arange(len(names))
        colors = ["#2196F3" if "Classical" not in r.notes and "ECDH" not in r.name
                  else "#FF9800" for r in results]

        fig, ax = plt.subplots(figsize=(14, 6))
        bars = ax.bar(x, means, yerr=stdevs, capsize=4, color=colors, alpha=0.85)
        ax.set_xticks(x)
        ax.set_xticklabels(names, rotation=30, ha="right", fontsize=9)
        ax.set_ylabel("Latency (µs)", fontsize=11)
        ax.set_title("HyPQ-Mess: Classical vs. Post-Quantum KEM Latency", fontsize=13, fontweight="bold")

        # Legend
        from matplotlib.patches import Patch
        legend_elements = [
            Patch(facecolor="#2196F3", label="Post-Quantum / Hybrid"),
            Patch(facecolor="#FF9800", label="Classical"),
        ]
        ax.legend(handles=legend_elements, loc="upper left")

        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight")
        console.print(f"[dim]Plot saved to {path}[/dim]")
        plt.close()
    except ImportError:
        console.print("[yellow]matplotlib not available; skipping plot.[/yellow]")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_all_benchmarks(
    iterations: int = 100,
    export: bool = False,
    plot: bool = True,
) -> List[BenchResult]:
    """
    Run the complete benchmark suite.

    Args:
        iterations: Number of iterations per benchmark (scales with operation).
        export    : Save results to JSON.
        plot      : Generate matplotlib chart.

    Returns:
        List of BenchResult objects.
    """
    console.rule("[bold cyan]HyPQ-Mess Benchmark Suite[/bold cyan]")

    benchmarks = [
        ("X25519 KeyGen", lambda: bench_x25519_keygen(iterations)),
        ("X25519 ECDH", lambda: bench_x25519_ecdh(iterations)),
        ("Hybrid KeyGen", lambda: bench_hybrid_keygen(iterations // 2)),
        ("Hybrid Encap+Decap", lambda: bench_hybrid_encap_decap(iterations // 2)),
        ("HKDF-SHA256", lambda: bench_hkdf(iterations * 2)),
        ("AES-256-GCM 1KB", lambda: bench_aesgcm_encrypt(1024, iterations * 2)),
        ("AES-256-GCM 64KB", lambda: bench_aesgcm_encrypt(65536, iterations)),
        ("Full Handshake", lambda: bench_full_handshake(max(iterations // 5, 10))),
    ]

    results = []
    for name, bench_fn in benchmarks:
        console.print(f"  Running: [cyan]{name}[/cyan]...", end=" ")
        try:
            result = bench_fn()
            results.append(result)
            console.print(f"[green]done[/green] ({result.mean_us:.1f} µs avg)")
        except Exception as exc:
            console.print(f"[red]FAILED: {exc}[/red]")

    print_results_table(results)

    if export:
        export_path = os.path.join(BENCHMARK_DIR, "results.json")
        export_results(results, export_path)

    if plot:
        plot_path = os.path.join(BENCHMARK_DIR, "latency_comparison.png")
        plot_results(results, plot_path)

    return results


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HyPQ-Mess Benchmark Suite")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--no-plot", action="store_true")
    args = parser.parse_args()
    run_all_benchmarks(
        iterations=args.iterations,
        export=args.export,
        plot=not args.no_plot,
    )
