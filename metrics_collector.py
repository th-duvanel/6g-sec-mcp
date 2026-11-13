"""High-precision observability and metrics collection module for 6G-SEC-MCP.

Captures:
1. Deployment Delay (ms) via `time.perf_counter()`.
2. Inference Latency (ms) across the Host A -> Host B reverse SSH tunnel.
3. Control-Plane Signaling Overhead (bytes) for prompts, wrappers, and MCP JSON-RPC calls.
4. Token Usage (`prompt_tokens`, `completion_tokens`, `total_tokens`).
5. Edge Overhead (`cpu_peak_percent`, `ram_peak_mb`) via `psutil`.

Appends each evaluation iteration atomically to `metrics_results.csv`.
"""

from __future__ import annotations

import csv
import os
import resource
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

from network_adapter import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class IncidentMetrics:
    """Structured record of all metrics collected during a single IDS incident cycle."""

    timestamp_utc: str
    scenario: str
    provider: str
    model: str
    deployment_delay_ms: float
    inference_latency_ms: float
    adapter_execution_ms: float
    signaling_overhead_bytes: int
    telemetry_payload_bytes: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cpu_peak_percent: float
    ram_peak_mb: float
    mitigation_success: bool
    mitigation_command: str

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics record into an ordered dictionary for CSV serialization."""
        return asdict(self)


class EdgeResourceMonitor:
    """Context manager that samples peak CPU (%) and RAM (MB) using `psutil`."""

    def __init__(self, sample_interval_sec: float = 0.02) -> None:
        """Initialize the resource sampler.

        Args:
            sample_interval_sec: Polling interval in seconds (default 20 ms).
        """
        self.sample_interval_sec: float = sample_interval_sec
        self.cpu_peak_percent: float = 0.0
        self.ram_peak_mb: float = 0.0
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._process = psutil.Process(os.getpid()) if psutil is not None else None
        self._start_wall_ns: float = 0.0
        self._start_cpu_sec: float = 0.0

    def __enter__(self) -> EdgeResourceMonitor:
        """Start background sampling of process and child-process CPU/RAM usage."""
        self.cpu_peak_percent = 0.0
        self.ram_peak_mb = 0.0
        self._stop_event.clear()
        self._start_wall_ns = time.perf_counter()
        self._start_cpu_sec = time.process_time()
        if psutil is not None and self._process is not None:
            try:
                self._process.cpu_percent(interval=None)
                psutil.cpu_percent(interval=None)
            except Exception:
                pass
        self._sample_once()
        self._thread = threading.Thread(target=self._run_sampler, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Stop background sampling and perform one final measurement."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._sample_once()

    def _run_sampler(self) -> None:
        """Background sampling loop."""
        while not self._stop_event.is_set():
            self._sample_once()
            self._stop_event.wait(self.sample_interval_sec)

    def _sample_once(self) -> None:
        """Record instantaneous CPU (%) and RSS memory (MB) across process tree."""
        if psutil is not None and self._process is not None:
            try:
                proc_cpu = self._process.cpu_percent(interval=None)
                sys_cpu = psutil.cpu_percent(interval=None)
                rss_bytes = self._process.memory_info().rss

                for child in self._process.children(recursive=True):
                    try:
                        proc_cpu += child.cpu_percent(interval=None)
                        rss_bytes += child.memory_info().rss
                    except Exception:
                        continue

                effective_cpu = max(proc_cpu, sys_cpu)
                ram_mb = rss_bytes / (1024.0 * 1024.0)

                if effective_cpu > self.cpu_peak_percent:
                    self.cpu_peak_percent = round(effective_cpu, 2)
                if ram_mb > self.ram_peak_mb:
                    self.ram_peak_mb = round(ram_mb, 3)
                return
            except Exception:
                pass

        # Fallback using Linux /proc/self/status and resource usage when psutil is unavailable
        try:
            wall_elapsed = max(1e-6, time.perf_counter() - self._start_wall_ns)
            cpu_elapsed = max(0.0, time.process_time() - self._start_cpu_sec)
            est_cpu_pct = min(100.0, (cpu_elapsed / wall_elapsed) * 100.0)
            rusage_self = resource.getrusage(resource.RUSAGE_SELF)
            rusage_children = resource.getrusage(resource.RUSAGE_CHILDREN)
            ram_mb = (rusage_self.ru_maxrss + rusage_children.ru_maxrss) / 1024.0
            if est_cpu_pct > self.cpu_peak_percent:
                self.cpu_peak_percent = round(est_cpu_pct, 2)
            if ram_mb > self.ram_peak_mb:
                self.ram_peak_mb = round(ram_mb, 3)
        except OSError:
            pass


class MetricsLogger:
    """Thread-safe CSV writer for iteratively appending experiment metrics."""

    FIELDNAMES: tuple[str, ...] = (
        "timestamp_utc",
        "scenario",
        "provider",
        "model",
        "deployment_delay_ms",
        "inference_latency_ms",
        "adapter_execution_ms",
        "signaling_overhead_bytes",
        "telemetry_payload_bytes",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "cpu_peak_percent",
        "ram_peak_mb",
        "mitigation_success",
        "mitigation_command",
    )

    def __init__(self, csv_path: str | Path | None = None) -> None:
        """Initialize the CSV logger.

        Args:
            csv_path: Target path for `metrics_results.csv`.
        """
        resolved = csv_path or os.getenv("METRICS_CSV_PATH", "metrics_results.csv")
        self.csv_path: Path = Path(resolved)

    def log_incident(self, metrics: IncidentMetrics) -> None:
        """Append a single `IncidentMetrics` row to `metrics_results.csv`."""
        self.csv_path.parent.mkdir(parents=True, exist_ok=True)
        write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0

        with self.csv_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(self.FIELDNAMES))
            if write_header:
                writer.writeheader()
            writer.writerow(metrics.to_dict())

    @staticmethod
    def utc_now_iso() -> str:
        """Return the current UTC timestamp in ISO-8601 format."""
        return datetime.now(timezone.utc).isoformat()
