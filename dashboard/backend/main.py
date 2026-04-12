"""
NEXUS SPECTER PRO — FastAPI Dashboard Backend
REST API for mission management, real-time monitoring, and report access
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
import logging, os, json, uuid
from datetime import datetime
from pathlib import Path

log = logging.getLogger("nsp.dashboard")

# ── In-memory store (replace with PostgreSQL in production) ─────────────────
MISSIONS  = {}
TARGETS   = {}
RESULTS   = {}
SESSIONS  = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("NEXUS SPECTER PRO Dashboard starting...")
    yield
    log.info("NEXUS SPECTER PRO Dashboard shutting down...")


app = FastAPI(
    title       = "NEXUS SPECTER PRO",
    description = "Military-Grade Automated Offensive Pentest Platform API — by OPTIMIUM NEXUS LLC",
    version     = "1.0.0-SPECTER",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["http://localhost:3000", "http://localhost:8080", "*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
    allow_credentials = True,
)

# ── HEALTH ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {"status": "operational", "platform": "NEXUS SPECTER PRO",
            "version": "1.0.0-SPECTER", "company": "OPTIMIUM NEXUS LLC",
            "timestamp": datetime.utcnow().isoformat()}


@app.get("/", tags=["System"])
async def root():
    return {
        "platform": "NEXUS SPECTER PRO",
        "version":  "1.0.0-SPECTER",
        "company":  "OPTIMIUM NEXUS LLC",
        "tagline":  "Invisible. Inevitable. Unstoppable.",
        "docs":     "/docs",
        "contact":  "contact@optimiumnexus.com",
        "website":  "https://www.optimiumnexus.com",
    }


# ── MISSIONS ─────────────────────────────────────────────────────────────────
@app.get("/api/missions", tags=["Missions"])
async def list_missions():
    return {"missions": list(MISSIONS.values()), "total": len(MISSIONS)}


@app.post("/api/missions", tags=["Missions"], status_code=201)
async def create_mission(payload: dict, background_tasks: BackgroundTasks):
    mission_id = f"NSP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:6].upper()}"
    mission = {
        "id":          mission_id,
        "name":        payload.get("name", f"Mission {mission_id}"),
        "target":      payload.get("target", ""),
        "mode":        payload.get("mode", "black_box"),
        "status":      "queued",
        "created_at":  datetime.utcnow().isoformat(),
        "updated_at":  datetime.utcnow().isoformat(),
        "phases":      payload.get("phases", "all"),
        "ai_assist":   payload.get("ai_assist", True),
        "progress":    0,
        "findings":    {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    }
    MISSIONS[mission_id] = mission
    background_tasks.add_task(_run_mission_bg, mission_id, payload)
    log.info(f"[API] Mission created: {mission_id}")
    return mission


async def _run_mission_bg(mission_id: str, payload: dict):
    import asyncio
    MISSIONS[mission_id]["status"]     = "running"
    MISSIONS[mission_id]["started_at"] = datetime.utcnow().isoformat()
    phases = ["recon", "enumeration", "vuln_scan", "exploitation", "post_exploit", "reporting"]
    for i, phase in enumerate(phases):
        await asyncio.sleep(2)
        MISSIONS[mission_id]["current_phase"] = phase
        MISSIONS[mission_id]["progress"]      = int((i + 1) / len(phases) * 100)
        MISSIONS[mission_id]["updated_at"]    = datetime.utcnow().isoformat()
    MISSIONS[mission_id]["status"]      = "complete"
    MISSIONS[mission_id]["completed_at"]= datetime.utcnow().isoformat()
    MISSIONS[mission_id]["progress"]    = 100


@app.get("/api/missions/{mission_id}", tags=["Missions"])
async def get_mission(mission_id: str):
    if mission_id not in MISSIONS:
        raise HTTPException(status_code=404, detail=f"Mission {mission_id} not found")
    return MISSIONS[mission_id]


@app.delete("/api/missions/{mission_id}", tags=["Missions"])
async def delete_mission(mission_id: str):
    if mission_id not in MISSIONS:
        raise HTTPException(status_code=404, detail="Mission not found")
    del MISSIONS[mission_id]
    return {"status": "deleted", "mission_id": mission_id}


# ── TARGETS ──────────────────────────────────────────────────────────────────
@app.get("/api/targets", tags=["Targets"])
async def list_targets():
    return {"targets": list(TARGETS.values()), "total": len(TARGETS)}


@app.post("/api/targets", tags=["Targets"], status_code=201)
async def add_target(payload: dict):
    target_id = str(uuid.uuid4())
    target = {
        "id":         target_id,
        "host":       payload.get("host", ""),
        "type":       payload.get("type", "domain"),
        "scope":      payload.get("scope", "in"),
        "notes":      payload.get("notes", ""),
        "added_at":   datetime.utcnow().isoformat(),
        "tags":       payload.get("tags", []),
    }
    TARGETS[target_id] = target
    return target


# ── RESULTS ──────────────────────────────────────────────────────────────────
@app.get("/api/results", tags=["Results"])
async def list_results(mission_id: str = None, severity: str = None):
    results = list(RESULTS.values())
    if mission_id:
        results = [r for r in results if r.get("mission_id") == mission_id]
    if severity:
        results = [r for r in results if r.get("severity") == severity]
    return {
        "results":  results,
        "total":    len(results),
        "summary":  {
            "critical": len([r for r in results if r.get("severity") == "critical"]),
            "high":     len([r for r in results if r.get("severity") == "high"]),
            "medium":   len([r for r in results if r.get("severity") == "medium"]),
            "low":      len([r for r in results if r.get("severity") == "low"]),
            "info":     len([r for r in results if r.get("severity") == "info"]),
        }
    }


@app.post("/api/results", tags=["Results"], status_code=201)
async def add_result(payload: dict):
    result_id = str(uuid.uuid4())
    result = {
        "id":          result_id,
        "mission_id":  payload.get("mission_id", ""),
        "name":        payload.get("name", ""),
        "severity":    payload.get("severity", "info"),
        "host":        payload.get("host", ""),
        "port":        payload.get("port"),
        "description": payload.get("description", ""),
        "evidence":    payload.get("evidence", ""),
        "cvss":        payload.get("cvss", 0.0),
        "cve":         payload.get("cve", ""),
        "remediation": payload.get("remediation", ""),
        "found_at":    datetime.utcnow().isoformat(),
        "tool":        payload.get("tool", "NSP"),
    }
    RESULTS[result_id] = result
    # Update mission findings count
    m_id = payload.get("mission_id")
    if m_id and m_id in MISSIONS:
        sev = payload.get("severity", "info")
        MISSIONS[m_id]["findings"][sev] = MISSIONS[m_id]["findings"].get(sev, 0) + 1
    return result


# ── REPORTS ──────────────────────────────────────────────────────────────────
@app.get("/api/reports", tags=["Reports"])
async def list_reports():
    reports_dir = Path("./reports")
    reports = []
    if reports_dir.exists():
        for f in reports_dir.rglob("*.html"):
            reports.append({"filename": f.name, "path": str(f),
                             "size_kb": round(f.stat().st_size / 1024, 1),
                             "created_at": datetime.fromtimestamp(f.stat().st_ctime).isoformat()})
        for f in reports_dir.rglob("*.pdf"):
            reports.append({"filename": f.name, "path": str(f),
                             "size_kb": round(f.stat().st_size / 1024, 1),
                             "created_at": datetime.fromtimestamp(f.stat().st_ctime).isoformat()})
    return {"reports": reports, "total": len(reports)}


@app.post("/api/reports/generate", tags=["Reports"])
async def generate_report(payload: dict, background_tasks: BackgroundTasks):
    mission_id = payload.get("mission_id", "")
    fmt        = payload.get("format", "both")
    background_tasks.add_task(_generate_report_bg, mission_id, fmt)
    return {"status": "generating", "mission_id": mission_id, "format": fmt}


async def _generate_report_bg(mission_id: str, fmt: str):
    import asyncio
    await asyncio.sleep(3)
    log.info(f"[REPORT] Generated report for mission {mission_id} in {fmt} format")


# ── STATS / DASHBOARD ────────────────────────────────────────────────────────
@app.get("/api/stats", tags=["Dashboard"])
async def get_stats():
    all_results = list(RESULTS.values())
    return {
        "total_missions":  len(MISSIONS),
        "active_missions": len([m for m in MISSIONS.values() if m.get("status") == "running"]),
        "total_targets":   len(TARGETS),
        "total_findings":  len(all_results),
        "by_severity": {
            "critical": len([r for r in all_results if r.get("severity") == "critical"]),
            "high":     len([r for r in all_results if r.get("severity") == "high"]),
            "medium":   len([r for r in all_results if r.get("severity") == "medium"]),
            "low":      len([r for r in all_results if r.get("severity") == "low"]),
            "info":     len([r for r in all_results if r.get("severity") == "info"]),
        },
        "recent_missions": sorted(MISSIONS.values(),
                                   key=lambda x: x.get("created_at",""), reverse=True)[:5],
        "platform": {
            "name":    "NEXUS SPECTER PRO",
            "version": "1.0.0-SPECTER",
            "company": "OPTIMIUM NEXUS LLC",
        }
    }
