"""
NEXUS SPECTER PRO — Mission Scheduler
Cron-like recurring mission scheduling with:
- APScheduler backend (interval / cron / one-shot)
- Persistent schedule store (SQLite / PostgreSQL)
- WebHook callbacks on completion
- Conflict detection (no duplicate concurrent scans on same target)
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, json, logging, uuid
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()
log = logging.getLogger("nsp.automation.scheduler")

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
    from apscheduler.executors.pool import ThreadPoolExecutor
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    APS_OK = True
except ImportError:
    APS_OK = False
    log.warning("[SCHED] APScheduler not installed — run: pip install apscheduler")


SCHEDULE_PRESETS = {
    "daily":        {"interval_hours": 24,   "description": "Every 24 hours"},
    "weekly":       {"interval_hours": 168,  "description": "Every 7 days"},
    "monthly":      {"cron": "0 2 1 * *",    "description": "1st of every month at 02:00"},
    "twice_weekly": {"cron": "0 3 * * 1,4",  "description": "Monday & Thursday at 03:00"},
    "continuous":   {"interval_hours": 6,    "description": "Every 6 hours"},
    "business_days":{"cron": "0 6 * * 1-5",  "description": "Mon-Fri at 06:00"},
}


@dataclass
class ScheduledMission:
    schedule_id:   str
    name:          str
    target:        str
    mode:          str          = "black_box"
    cron_expr:     str          = ""
    interval_hours:int          = 0
    enabled:       bool         = True
    created_at:    str          = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_run:      str          = ""
    next_run:      str          = ""
    run_count:     int          = 0
    config:        dict         = field(default_factory=dict)
    notify_on:     list         = field(default_factory=lambda: ["complete","critical"])
    tags:          list         = field(default_factory=list)


@dataclass
class SchedulerStats:
    total_schedules:  int  = 0
    active_schedules: int  = 0
    running_jobs:     int  = 0
    total_runs:       int  = 0
    next_run:         str  = ""


class MissionScheduler:
    """
    Recurring mission scheduler for NEXUS SPECTER PRO.
    Wraps APScheduler with NSP-specific logic:
    - Prevents concurrent scans on the same target
    - Persists schedules to SQLite (survives restarts)
    - Triggers AlertEngine on completion/critical findings
    - Supports cron expressions + interval presets
    """

    STORE_PATH = Path("/tmp/nsp_schedules.json")

    def __init__(
        self,
        db_url:        str = None,
        max_workers:   int = 4,
        alert_engine   = None,
    ):
        self.db_url       = db_url or os.getenv("DATABASE_URL",
                             "sqlite:////tmp/nsp_apscheduler.db")
        self.max_workers  = max_workers
        self.alert_engine = alert_engine
        self._schedules:  dict[str, ScheduledMission] = {}
        self._running:    set  = set()          # targets currently scanning
        self._scheduler   = None
        self._load_store()

    def _load_store(self):
        if self.STORE_PATH.exists():
            try:
                raw = json.loads(self.STORE_PATH.read_text())
                for sid, data in raw.items():
                    self._schedules[sid] = ScheduledMission(**data)
                log.info(f"[SCHED] Loaded {len(self._schedules)} schedules from store")
            except Exception as e:
                log.warning(f"[SCHED] Store load error: {e}")

    def _save_store(self):
        data = {sid: s.__dict__ for sid, s in self._schedules.items()}
        self.STORE_PATH.write_text(json.dumps(data, indent=2, default=str))

    def _init_apscheduler(self):
        if not APS_OK:
            return None
        jobstores  = {"default": SQLAlchemyJobStore(url=self.db_url)}
        executors  = {"default": ThreadPoolExecutor(self.max_workers)}
        scheduler  = BackgroundScheduler(
            jobstores  = jobstores,
            executors  = executors,
            job_defaults = {"coalesce": True, "max_instances": 1},
        )
        return scheduler

    def start(self):
        """Start the background scheduler."""
        self._scheduler = self._init_apscheduler()
        if self._scheduler:
            self._scheduler.start()
            console.print("[bold #00FFD4]  ✅ Mission Scheduler started[/bold #00FFD4]")
            self._register_all()
        else:
            console.print("[bold #FFD700]  ⚠ Running in mock mode — APScheduler unavailable[/bold #FFD700]")

    def stop(self):
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown()
            console.print("[#00FFD4]  [SCHED] Scheduler stopped[/#00FFD4]")

    def _register_all(self):
        """Re-register all saved schedules with APScheduler on startup."""
        for sid, sched in self._schedules.items():
            if sched.enabled:
                self._register_job(sched)

    def _register_job(self, sched: ScheduledMission):
        if not self._scheduler:
            return
        job_id = f"nsp_{sched.schedule_id}"
        # Remove existing job if present
        try:
            self._scheduler.remove_job(job_id)
        except Exception:
            pass

        kwargs = {"schedule_id": sched.schedule_id}
        if sched.cron_expr:
            parts   = sched.cron_expr.split()
            trigger = CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2],
                month=parts[3], day_of_week=parts[4]
            )
        else:
            trigger = IntervalTrigger(hours=max(sched.interval_hours, 1))

        self._scheduler.add_job(
            self._execute_mission,
            trigger  = trigger,
            id       = job_id,
            name     = sched.name,
            kwargs   = kwargs,
            replace_existing = True,
        )
        log.info(f"[SCHED] Registered job: {job_id}")

    def _execute_mission(self, schedule_id: str):
        """Background job: execute a scheduled mission."""
        sched = self._schedules.get(schedule_id)
        if not sched:
            return
        if sched.target in self._running:
            log.warning(f"[SCHED] Skipping {sched.target} — already running")
            return

        self._running.add(sched.target)
        session_id = f"NSP-SCHED-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        log.info(f"[SCHED] Executing: {sched.name} → {sched.target} ({session_id})")

        try:
            # Update schedule metadata
            sched.last_run  = datetime.utcnow().isoformat()
            sched.run_count += 1
            self._save_store()

            # Run orchestrator
            from nsp.core.orchestrator import NSPOrchestrator
            import argparse
            args = argparse.Namespace(
                target     = sched.target,
                targets    = None,
                mode       = sched.mode,
                phases     = sched.config.get("phases","all"),
                ai_assist  = sched.config.get("ai_assist", False),
                output     = f"/app/reports/{session_id}",
                report_format = "both",
                no_report  = False,
                verbose    = False,
                debug      = False,
                quiet      = True,
                skip       = None,
                stealth    = sched.config.get("stealth", False),
                aggressive = False,
                scope      = "config/scope.yaml",
                exclude    = None,
                creds      = None,
                provider   = None,
                mission    = None,
                ai_model   = "claude-opus-4-5",
                ai_plan    = False,
                dashboard  = False,
                port       = 8080,
                list_modules = False,
                version    = False,
            )
            orchestrator = NSPOrchestrator(args)
            orchestrator.run()

            # Notify
            if self.alert_engine and "complete" in sched.notify_on:
                self.alert_engine.send(
                    title   = f"✅ Scheduled Mission Complete: {sched.name}",
                    message = f"Target: {sched.target} | Session: {session_id}",
                    level   = "info",
                )
        except Exception as e:
            log.error(f"[SCHED] Mission failed: {e}")
            if self.alert_engine:
                self.alert_engine.send(
                    title   = f"❌ Scheduled Mission Failed: {sched.name}",
                    message = str(e),
                    level   = "error",
                )
        finally:
            self._running.discard(sched.target)

    # ── Public API ─────────────────────────────────────────────────────────────
    def add(
        self,
        name:          str,
        target:        str,
        mode:          str  = "black_box",
        preset:        str  = None,
        cron_expr:     str  = None,
        interval_hours:int  = 0,
        config:        dict = None,
        notify_on:     list = None,
        tags:          list = None,
    ) -> ScheduledMission:
        """Add a new recurring mission schedule."""
        sid = uuid.uuid4().hex[:10].upper()

        # Apply preset
        if preset and preset in SCHEDULE_PRESETS:
            p = SCHEDULE_PRESETS[preset]
            cron_expr      = p.get("cron","")
            interval_hours = p.get("interval_hours", 0)

        sched = ScheduledMission(
            schedule_id    = sid,
            name           = name,
            target         = target,
            mode           = mode,
            cron_expr      = cron_expr or "",
            interval_hours = interval_hours,
            config         = config or {},
            notify_on      = notify_on or ["complete","critical"],
            tags           = tags or [],
        )
        self._schedules[sid] = sched
        self._save_store()
        if self._scheduler:
            self._register_job(sched)

        console.print(f"[bold #00FFD4]  ✅ Schedule added: {name} → {target} "
                       f"[{preset or cron_expr or f'{interval_hours}h'}][/bold #00FFD4]")
        return sched

    def remove(self, schedule_id: str):
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            self._save_store()
            if self._scheduler:
                try:
                    self._scheduler.remove_job(f"nsp_{schedule_id}")
                except Exception:
                    pass
            console.print(f"[#00FFD4]  [SCHED] Removed: {schedule_id}[/#00FFD4]")

    def enable(self, schedule_id: str):
        if schedule_id in self._schedules:
            self._schedules[schedule_id].enabled = True
            self._save_store()
            self._register_job(self._schedules[schedule_id])

    def disable(self, schedule_id: str):
        if schedule_id in self._schedules:
            self._schedules[schedule_id].enabled = False
            self._save_store()
            if self._scheduler:
                try: self._scheduler.pause_job(f"nsp_{schedule_id}")
                except Exception: pass

    def list_schedules(self) -> list:
        return list(self._schedules.values())

    def get_stats(self) -> SchedulerStats:
        active = sum(1 for s in self._schedules.values() if s.enabled)
        runs   = sum(s.run_count for s in self._schedules.values())
        return SchedulerStats(
            total_schedules  = len(self._schedules),
            active_schedules = active,
            running_jobs     = len(self._running),
            total_runs       = runs,
        )

    def print_schedules(self):
        table = Table(
            title="[bold #7B00FF]⏰ MISSION SCHEDULES[/bold #7B00FF]",
            border_style="#7B00FF", header_style="bold #00FFD4",
        )
        table.add_column("ID",       width=12)
        table.add_column("Name",     width=25)
        table.add_column("Target",   width=25)
        table.add_column("Mode",     width=12)
        table.add_column("Schedule", width=18)
        table.add_column("Runs",     width=6,  justify="right")
        table.add_column("Status",   width=10)
        table.add_column("Last Run", width=12)

        for s in self._schedules.values():
            schedule_str = s.cron_expr or f"every {s.interval_hours}h"
            status = "[bold #00FFD4]ACTIVE[/bold #00FFD4]" if s.enabled else "[dim]PAUSED[/dim]"
            table.add_row(
                s.schedule_id, s.name[:25], s.target[:25],
                s.mode, schedule_str[:18],
                str(s.run_count), status,
                s.last_run[:10] if s.last_run else "—",
            )
        console.print(table)
        if not self._schedules:
            console.print("[dim]  No schedules configured.[/dim]")

    def run_now(self, schedule_id: str):
        """Immediately trigger a scheduled mission (outside normal schedule)."""
        console.print(f"[bold #7B00FF]  ⚡ Running schedule {schedule_id} immediately...[/bold #7B00FF]")
        import threading
        t = threading.Thread(target=self._execute_mission, args=(schedule_id,))
        t.daemon = True
        t.start()
