"""
NEXUS SPECTER PRO — Celery Async Task Workers
Manages long-running missions as distributed async tasks.
Phases run as individual tasks with retry, monitoring, and result persistence.
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, logging
from datetime import datetime
from celery import Celery
from celery.utils.log import get_task_logger
from celery.signals import task_prerun, task_postrun, task_failure

log = get_task_logger(__name__)

# ── App configuration ─────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DB_URL    = os.getenv("DATABASE_URL", "postgresql://nsp:nsp@localhost:5432/nexus_specter")

app = Celery(
    "nexus_specter_pro",
    broker           = REDIS_URL,
    backend          = REDIS_URL,
    include          = ["nsp.core.celery_tasks"],
)

app.conf.update(
    # Serialization
    task_serializer         = "json",
    result_serializer       = "json",
    accept_content          = ["json"],
    result_expires          = 86400,          # 24h

    # Concurrency
    worker_concurrency      = int(os.getenv("CELERY_CONCURRENCY", "4")),
    worker_prefetch_multiplier = 1,           # one task at a time per worker
    task_acks_late          = True,           # ack after completion (safe)

    # Retry defaults
    task_max_retries        = 3,
    task_default_retry_delay= 60,

    # Monitoring
    worker_send_task_events  = True,
    task_send_sent_event     = True,
    task_track_started       = True,

    # Beat schedule (periodic tasks)
    beat_schedule = {
        "update-nuclei-templates": {
            "task":     "nsp.core.celery_tasks.update_nuclei_templates",
            "schedule": 86400,              # daily
        },
        "session-cleanup": {
            "task":     "nsp.core.celery_tasks.cleanup_old_sessions",
            "schedule": 3600,              # hourly
        },
        "health-check": {
            "task":     "nsp.core.celery_tasks.health_check",
            "schedule": 300,              # every 5 minutes
        },
    },
    timezone                = "UTC",
    enable_utc              = True,
)


# ── Signal hooks ──────────────────────────────────────────────────────────────
@task_prerun.connect
def task_starting(task_id, task, args, kwargs, **kw):
    log.info(f"[TASK] Starting: {task.name} | ID: {task_id}")

@task_postrun.connect
def task_done(task_id, task, retval, state, **kw):
    log.info(f"[TASK] Done: {task.name} | ID: {task_id} | State: {state}")

@task_failure.connect
def task_failed(task_id, exception, traceback, **kw):
    log.error(f"[TASK] Failed: {task_id} | Error: {exception}")


# ── Mission orchestration tasks ────────────────────────────────────────────────
@app.task(bind=True, name="nsp.mission.launch", max_retries=1, queue="missions")
def launch_mission(self, mission_id: str, config: dict):
    """
    Main mission orchestration task.
    Chains all phase sub-tasks and reports progress.
    """
    log.info(f"[MISSION] Launching: {mission_id} | target: {config.get('target')}")
    try:
        from nsp.core.session_manager import SessionManager
        sm      = SessionManager()
        session = sm.create(
            mission_name = config.get("name","Mission"),
            target       = config.get("target",""),
            mode         = config.get("mode","black_box"),
        )
        session_id = session.session_id
        log.info(f"[MISSION] Session: {session_id}")

        # Chain phase tasks
        chain_result = (
            run_recon_phase.si(session_id, config)        |
            run_enumeration_phase.si(session_id, config)  |
            run_vuln_scan_phase.si(session_id, config)    |
            run_exploitation_phase.si(session_id, config) |
            run_post_exploit_phase.si(session_id, config) |
            run_reporting_phase.si(session_id, config)
        ).apply_async()

        return {"session_id": session_id, "chain_id": str(chain_result)}
    except Exception as exc:
        log.error(f"[MISSION] Launch failed: {exc}")
        raise self.retry(exc=exc, countdown=30)


@app.task(bind=True, name="nsp.phase.recon", queue="phases",
          soft_time_limit=1800, time_limit=2400)
def run_recon_phase(self, session_id: str, config: dict) -> dict:
    """Phase 1 — Ghost Recon."""
    log.info(f"[RECON] Starting | session: {session_id}")
    target = config.get("target","")
    results = {}
    try:
        # OSINT
        from nsp.recon.passive.osint_engine import OSINTEngine
        results["osint"] = OSINTEngine(target).run()
    except Exception as e:
        log.warning(f"[RECON] OSINT error: {e}")
    try:
        # Subdomain
        from nsp.recon.active.subdomain_enum import SubdomainEnumerator
        results["subdomains"] = SubdomainEnumerator(target).run()
    except Exception as e:
        log.warning(f"[RECON] Subdomain error: {e}")
    try:
        # Cloud
        from nsp.recon.active.cloud_recon import CloudRecon
        results["cloud"] = CloudRecon(target).run()
    except Exception as e:
        log.warning(f"[RECON] Cloud recon error: {e}")
    try:
        # Email
        from nsp.recon.passive.email_harvester import EmailHarvester
        results["emails"] = EmailHarvester(target).run()
    except Exception as e:
        log.warning(f"[RECON] Email harvest error: {e}")

    _save_phase(session_id, "recon", results)
    log.info(f"[RECON] Complete | session: {session_id}")
    return {"session_id": session_id, "phase": "recon", "config": config}


@app.task(bind=True, name="nsp.phase.enumeration", queue="phases",
          soft_time_limit=1800, time_limit=2400)
def run_enumeration_phase(self, prev: dict, session_id: str = None,
                           config: dict = None) -> dict:
    """Phase 2 — Deep Mapping."""
    # Support both chained (prev dict) and direct call
    if isinstance(prev, dict) and "session_id" in prev:
        session_id = prev["session_id"]
        config     = prev.get("config", config or {})
    log.info(f"[ENUM] Starting | session: {session_id}")
    target  = config.get("target","") if config else ""
    results = {}
    try:
        from nsp.enumeration.web.dir_fuzzer import DirFuzzer
        results["dirs"] = DirFuzzer(f"https://{target}").run()
    except Exception as e:
        log.warning(f"[ENUM] Dir fuzz error: {e}")
    try:
        from nsp.enumeration.web.api_enum import APIEnumerator
        results["apis"] = APIEnumerator(f"https://{target}").run()
    except Exception as e:
        log.warning(f"[ENUM] API enum error: {e}")

    _save_phase(session_id, "enumeration", results)
    return {"session_id": session_id, "phase": "enumeration", "config": config}


@app.task(bind=True, name="nsp.phase.vuln_scan", queue="phases",
          soft_time_limit=3600, time_limit=4800)
def run_vuln_scan_phase(self, prev: dict, session_id: str = None,
                         config: dict = None) -> dict:
    """Phase 3 — Specter Scan."""
    if isinstance(prev, dict) and "session_id" in prev:
        session_id = prev["session_id"]
        config     = prev.get("config", config or {})
    log.info(f"[VULN] Starting | session: {session_id}")
    target  = config.get("target","") if config else ""
    results = {}
    try:
        from nsp.vuln_scan.web_scanner import WebScanner
        results["web_scan"] = WebScanner(f"https://{target}").run()
    except Exception as e:
        log.warning(f"[VULN] Web scan error: {e}")
    try:
        from nsp.vuln_scan.ssl_scanner import SSLScanner
        results["ssl"] = SSLScanner(target).run()
    except Exception as e:
        log.warning(f"[VULN] SSL scan error: {e}")
    try:
        from nsp.vuln_scan.nuclei_runner import NucleiRunner
        results["nuclei"] = NucleiRunner([f"https://{target}"]).run()
    except Exception as e:
        log.warning(f"[VULN] Nuclei error: {e}")

    _save_phase(session_id, "vuln_scan", results)
    return {"session_id": session_id, "phase": "vuln_scan", "config": config}


@app.task(bind=True, name="nsp.phase.exploitation", queue="phases",
          soft_time_limit=1800, time_limit=2400)
def run_exploitation_phase(self, prev: dict, session_id: str = None,
                            config: dict = None) -> dict:
    """Phase 4 — Specter Strike (authorization required)."""
    if isinstance(prev, dict) and "session_id" in prev:
        session_id = prev["session_id"]
        config     = prev.get("config", config or {})
    log.info(f"[EXPLOIT] Phase | session: {session_id} | requires authorization")
    _save_phase(session_id, "exploitation", {"status": "phase_reached"})
    return {"session_id": session_id, "phase": "exploitation", "config": config}


@app.task(bind=True, name="nsp.phase.post_exploit", queue="phases",
          soft_time_limit=1800, time_limit=2400)
def run_post_exploit_phase(self, prev: dict, session_id: str = None,
                            config: dict = None) -> dict:
    """Phase 5 — Ghost Mode."""
    if isinstance(prev, dict) and "session_id" in prev:
        session_id = prev["session_id"]
        config     = prev.get("config", config or {})
    log.info(f"[POST] Phase | session: {session_id}")
    _save_phase(session_id, "post_exploit", {"status": "phase_reached"})
    return {"session_id": session_id, "phase": "post_exploit", "config": config}


@app.task(bind=True, name="nsp.phase.reporting", queue="phases",
          soft_time_limit=600, time_limit=900)
def run_reporting_phase(self, prev: dict, session_id: str = None,
                         config: dict = None) -> dict:
    """Phase 6 — Specter Report."""
    if isinstance(prev, dict) and "session_id" in prev:
        session_id = prev["session_id"]
        config     = prev.get("config", config or {})
    log.info(f"[REPORT] Generating | session: {session_id}")
    try:
        from nsp.core.session_manager import SessionManager
        sm      = SessionManager()
        session = sm.get(session_id)
        if session:
            from nsp.reporting.report_generator import ReportGenerator
            rg = ReportGenerator(
                results    = {"vuln_scan": session.findings},
                session_id = session_id,
                output_dir = "/app/reports",
                target     = config.get("target","") if config else "",
            )
            report = rg.generate_all()
            _save_phase(session_id, "reporting", report)
            sm.complete(session_id)
            return {"session_id": session_id, "report": report}
    except Exception as e:
        log.error(f"[REPORT] Error: {e}")
    return {"session_id": session_id, "phase": "reporting"}


# ── Maintenance tasks ─────────────────────────────────────────────────────────
@app.task(name="nsp.maintenance.nuclei_update", queue="maintenance")
def update_nuclei_templates():
    import subprocess, shutil
    if shutil.which("nuclei"):
        result = subprocess.run(["nuclei","-update-templates","-silent"],
                                 capture_output=True, timeout=300)
        log.info(f"[MAINTENANCE] Nuclei templates updated: {result.returncode}")
    return {"status":"ok","ts":datetime.utcnow().isoformat()}


@app.task(name="nsp.maintenance.cleanup", queue="maintenance")
def cleanup_old_sessions(max_age_hours: int = 168):
    from pathlib import Path
    from nsp.core.session_manager import SessionManager
    sm      = SessionManager()
    sessions= sm.list_sessions()
    cutoff  = datetime.utcnow().timestamp() - (max_age_hours * 3600)
    cleaned = 0
    for s in sessions:
        try:
            created = datetime.fromisoformat(s["created_at"]).timestamp()
            if created < cutoff and s["status"] == "complete":
                sm.delete(s["id"])
                cleaned += 1
        except Exception:
            pass
    log.info(f"[MAINTENANCE] Cleaned {cleaned} old sessions")
    return {"cleaned": cleaned}


@app.task(name="nsp.maintenance.health", queue="maintenance")
def health_check():
    checks = {"redis": False, "db": False, "nuclei": False}
    try:
        import redis as redis_lib
        r = redis_lib.from_url(REDIS_URL)
        r.ping()
        checks["redis"] = True
    except Exception:
        pass
    import shutil
    checks["nuclei"] = bool(shutil.which("nuclei"))
    log.info(f"[HEALTH] {checks}")
    return {"ts": datetime.utcnow().isoformat(), "checks": checks}


# ── Helper ────────────────────────────────────────────────────────────────────
def _save_phase(session_id: str, phase: str, results: dict):
    try:
        from nsp.core.session_manager import SessionManager
        SessionManager().add_phase(session_id, phase, results)
    except Exception as e:
        log.warning(f"[CELERY] Could not save phase {phase} to session: {e}")
