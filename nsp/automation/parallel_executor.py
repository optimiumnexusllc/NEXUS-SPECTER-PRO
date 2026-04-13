"""
NEXUS SPECTER PRO — Parallel Executor
Asyncio-based concurrent scan engine for hundreds of targets.
Features: rate limiting, per-target timeouts, live progress, result aggregation.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import asyncio, logging, time, json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Coroutine, Any
from rich.console import Console
from rich.progress import (Progress, SpinnerColumn, BarColumn,
                           TextColumn, TimeElapsedColumn, MofNCompleteColumn)
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.automation.parallel")


@dataclass
class TargetResult:
    target:      str
    status:      str        # success | failed | timeout | skipped
    duration:    float      = 0.0
    findings:    dict       = field(default_factory=dict)
    error:       str        = ""
    session_id:  str        = ""
    started_at:  str        = ""
    finished_at: str        = ""


@dataclass
class ExecutionSummary:
    total:       int   = 0
    succeeded:   int   = 0
    failed:      int   = 0
    timed_out:   int   = 0
    skipped:     int   = 0
    duration_s:  float = 0.0
    critical_targets: list = field(default_factory=list)
    results:     list  = field(default_factory=list)


class ParallelExecutor:
    """
    High-throughput parallel scan executor for NEXUS SPECTER PRO.
    Manages a semaphore-bounded asyncio worker pool.
    Supports:
    - Any async scan coroutine as the worker function
    - Per-target timeout
    - Global rate limit (scans/second)
    - Live rich progress bar
    - Result aggregation + summary report
    """

    def __init__(
        self,
        max_concurrent:  int   = 10,
        target_timeout:  int   = 1800,    # 30 min per target
        rate_limit:      float = 2.0,     # scans/second
        output_dir:      str   = "/tmp/nsp_parallel",
        stop_on_error:   bool  = False,
    ):
        self.max_concurrent  = max_concurrent
        self.target_timeout  = target_timeout
        self.rate_limit      = rate_limit
        self.output_dir      = Path(output_dir)
        self.stop_on_error   = stop_on_error
        self._semaphore      = None
        self._rate_delay     = 1.0 / rate_limit if rate_limit > 0 else 0
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Default scan worker ────────────────────────────────────────────────────
    async def _default_worker(self, target: str, mode: str = "black_box") -> dict:
        """
        Default async scan worker — wraps NSP orchestrator.
        Replace with custom coroutine for specialised scanning.
        """
        import asyncio
        session_id = f"NSP-PAR-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        # Simulate orchestrator run asynchronously
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, self._sync_scan, target, mode, session_id)
            return result
        except Exception as e:
            return {"error": str(e), "target": target}

    def _sync_scan(self, target: str, mode: str, session_id: str) -> dict:
        """Synchronous scan wrapped for asyncio executor."""
        try:
            import argparse
            from nsp.core.orchestrator import NSPOrchestrator
            args = argparse.Namespace(
                target=target, targets=None, mode=mode,
                phases="recon,vuln_scan", ai_assist=False,
                output=str(self.output_dir / session_id),
                report_format="json", no_report=False,
                verbose=False, debug=False, quiet=True,
                skip=None, stealth=False, aggressive=False,
                scope="config/scope.yaml", exclude=None,
                creds=None, provider=None, mission=None,
                ai_model="claude-opus-4-5", ai_plan=False,
                dashboard=False, port=8080, list_modules=False, version=False,
            )
            orch = NSPOrchestrator(args)
            orch.run()
            return {"session_id": session_id, "target": target, "status": "success"}
        except Exception as e:
            return {"error": str(e), "target": target}

    # ── Core execution ─────────────────────────────────────────────────────────
    async def _run_single(
        self,
        target:   str,
        worker:   Callable,
        progress,
        task_id,
        **kwargs,
    ) -> TargetResult:
        """Execute a single target with timeout and semaphore."""
        async with self._semaphore:
            started = datetime.utcnow().isoformat()
            t0      = time.time()
            result  = TargetResult(target=target, started_at=started)

            try:
                # Rate limiting delay
                await asyncio.sleep(self._rate_delay)

                # Execute with timeout
                raw = await asyncio.wait_for(
                    worker(target, **kwargs),
                    timeout=self.target_timeout,
                )
                elapsed = round(time.time() - t0, 2)
                result.status      = raw.get("status","success") if isinstance(raw,dict) else "success"
                result.findings    = raw if isinstance(raw, dict) else {}
                result.duration    = elapsed
                result.session_id  = raw.get("session_id","") if isinstance(raw,dict) else ""
                result.finished_at = datetime.utcnow().isoformat()

            except asyncio.TimeoutError:
                result.status  = "timeout"
                result.error   = f"Timeout after {self.target_timeout}s"
                result.duration= self.target_timeout
                log.warning(f"[PARALLEL] Timeout: {target}")

            except Exception as e:
                result.status  = "failed"
                result.error   = str(e)[:200]
                result.duration= round(time.time() - t0, 2)
                log.error(f"[PARALLEL] Error on {target}: {e}")
                if self.stop_on_error:
                    raise

            finally:
                progress.advance(task_id)

            return result

    async def _run_all(
        self,
        targets:  list,
        worker:   Callable,
        **kwargs,
    ) -> list:
        """Run all targets concurrently up to max_concurrent."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        results         = []

        with Progress(
            SpinnerColumn(style="#7B00FF"),
            TextColumn("[bold #7B00FF]{task.description}"),
            BarColumn(bar_width=35, style="#7B00FF", complete_style="#00FFD4"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console, transient=False,
        ) as progress:
            task_id = progress.add_task(
                f"[#00FFD4]Scanning {len(targets)} targets...",
                total=len(targets),
            )
            tasks = [
                self._run_single(t, worker, progress, task_id, **kwargs)
                for t in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=False)

        return list(results)

    # ── Aggregation ────────────────────────────────────────────────────────────
    def _aggregate(self, results: list, duration: float) -> ExecutionSummary:
        summary = ExecutionSummary(
            total     = len(results),
            duration_s= round(duration, 2),
            results   = [r.__dict__ for r in results],
        )
        for r in results:
            if r.status == "success":   summary.succeeded += 1
            elif r.status == "timeout": summary.timed_out += 1
            elif r.status == "skipped": summary.skipped   += 1
            else:                       summary.failed     += 1

            # Flag targets with critical findings
            crit = len(r.findings.get("by_severity",{}).get("critical",[]))
            if crit > 0:
                summary.critical_targets.append({
                    "target":   r.target,
                    "critical": crit,
                    "session":  r.session_id,
                })
        return summary

    def _print_summary(self, summary: ExecutionSummary):
        table = Table(
            title=f"[bold #7B00FF]⚡ PARALLEL EXECUTION SUMMARY[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("Metric",   style="#00FFD4", width=22)
        table.add_column("Value",    style="white",   width=15)

        table.add_row("Total Targets",       str(summary.total))
        table.add_row("Succeeded",           f"[bold #00FFD4]{summary.succeeded}[/bold #00FFD4]")
        table.add_row("Failed",              f"[bold #FF003C]{summary.failed}[/bold #FF003C]")
        table.add_row("Timed Out",           f"[bold #FF8C00]{summary.timed_out}[/bold #FF8C00]")
        table.add_row("Skipped",             str(summary.skipped))
        table.add_row("Total Duration",      f"{summary.duration_s}s")
        table.add_row("Avg per Target",      f"{summary.duration_s/max(summary.total,1):.1f}s")
        table.add_row("Critical Targets",    f"[bold #FF003C]{len(summary.critical_targets)}[/bold #FF003C]")
        table.add_row("Max Concurrent",      str(self.max_concurrent))
        console.print(table)

        if summary.critical_targets:
            console.print("\n  [bold #FF003C]⚡ CRITICAL FINDINGS:[/bold #FF003C]")
            for t in summary.critical_targets[:5]:
                console.print(f"    → {t['target']} — {t['critical']} critical")

    def _save_results(self, summary: ExecutionSummary) -> Path:
        out = self.output_dir / f"parallel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        out.write_text(json.dumps(summary.__dict__, indent=2, default=str))
        return out

    # ── Public API ─────────────────────────────────────────────────────────────
    def run(
        self,
        targets:  list,
        worker:   Callable = None,
        mode:     str      = "black_box",
        **kwargs,
    ) -> ExecutionSummary:
        """
        Execute scans on all targets in parallel.
        worker: async coroutine function(target, **kwargs) → dict
                If None, uses the built-in NSP orchestrator worker.
        """
        console.print(
            f"[bold #7B00FF]  ⚡ Parallel Executor — {len(targets)} targets | "
            f"concurrency: {self.max_concurrent} | "
            f"timeout: {self.target_timeout}s[/bold #7B00FF]"
        )
        if not targets:
            console.print("[dim]  No targets provided.[/dim]")
            return ExecutionSummary()

        scan_worker = worker or self._default_worker
        t0  = time.time()

        try:
            loop    = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            results = loop.run_until_complete(
                self._run_all(targets, scan_worker, **kwargs)
            )
        finally:
            loop.close()

        duration = time.time() - t0
        summary  = self._aggregate(results, duration)
        self._print_summary(summary)
        out = self._save_results(summary)
        console.print(f"\n[bold #00FFD4]  ✅ Parallel execution complete in {duration:.1f}s "
                       f"| Results: {out}[/bold #00FFD4]")
        return summary

    @staticmethod
    def chunk_targets(targets: list, chunk_size: int = 50) -> list:
        """Split large target lists into manageable chunks."""
        return [targets[i:i+chunk_size] for i in range(0, len(targets), chunk_size)]
