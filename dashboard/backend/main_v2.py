"""
NEXUS SPECTER PRO — FastAPI Dashboard Backend v2
WebSockets real-time updates + JWT authentication + complete REST API
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import asyncio, json, logging, os, uuid
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import (FastAPI, HTTPException, Depends, BackgroundTasks,
                     WebSocket, WebSocketDisconnect, status)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field

log = logging.getLogger("nsp.dashboard.v2")

# ── JWT (simple HS256) ───────────────────────────────────────────────────────
try:
    from jose import jwt as jose_jwt, JWTError
    JWT_OK = True
except ImportError:
    JWT_OK = False
    log.warning("python-jose not installed — JWT auth disabled. Run: pip install python-jose")

SECRET_KEY  = os.getenv("NSP_SECRET_KEY", "nsp-specter-change-this-in-production")
ALGORITHM   = "HS256"
TOKEN_HOURS = 24

# ── In-memory store ──────────────────────────────────────────────────────────
DB: dict = {
    "missions": {},
    "targets":  {},
    "results":  {},
    "users":    {"admin": {"password": "nsp_admin_2025!", "role": "admin"}},
}

# ── WebSocket connection manager ─────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        log.info(f"[WS] Client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws) if ws in self.active else None
        log.info(f"[WS] Client disconnected. Total: {len(self.active)}")

    async def broadcast(self, event: str, data: dict):
        msg = json.dumps({"event": event, "data": data,
                          "ts": datetime.utcnow().isoformat()})
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

ws_manager = ConnectionManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("NSP Dashboard v2 starting...")
    yield
    log.info("NSP Dashboard v2 shutting down...")


app = FastAPI(
    title       = "NEXUS SPECTER PRO — Dashboard API",
    description = "Military-Grade Automated Offensive Pentest Platform\nby OPTIMIUM NEXUS LLC",
    version     = "2.0.0-SPECTER",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=True,
)

security = HTTPBearer(auto_error=False)


# ── Pydantic Models ──────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class MissionCreate(BaseModel):
    name:       str
    target:     str
    mode:       str = "black_box"
    phases:     str = "all"
    ai_assist:  bool = True
    scope_file: Optional[str] = None

class TargetCreate(BaseModel):
    host:   str
    type:   str = "domain"
    scope:  str = "in"
    notes:  str = ""
    tags:   list = Field(default_factory=list)

class ResultCreate(BaseModel):
    mission_id:  str
    name:        str
    severity:    str
    host:        str
    port:        Optional[int] = None
    description: str = ""
    evidence:    str = ""
    cvss:        float = 0.0
    cve:         str = ""
    cwe:         str = ""
    remediation: str = ""
    tool:        str = "NSP"
    mitre:       str = ""
    tags:        list = Field(default_factory=list)


# ── JWT helpers ───────────────────────────────────────────────────────────────
def create_token(username: str, role: str) -> str:
    if not JWT_OK:
        return "jwt-not-available"
    exp = datetime.utcnow() + timedelta(hours=TOKEN_HOURS)
    return jose_jwt.encode(
        {"sub": username, "role": role, "exp": exp},
        SECRET_KEY, algorithm=ALGORITHM,
    )

def verify_token(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Authorization required")
    if not JWT_OK:
        return {"sub": "admin", "role": "admin"}   # fallback if jose not installed
    try:
        payload = jose_jwt.decode(creds.credentials, SECRET_KEY,
                                   algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ── AUTH ─────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login", tags=["Auth"])
async def login(req: LoginRequest):
    user = DB["users"].get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(req.username, user["role"])
    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   TOKEN_HOURS * 3600,
        "username":     req.username,
        "role":         user["role"],
    }

@app.get("/api/auth/me", tags=["Auth"])
async def me(user: dict = Depends(verify_token)):
    return {"username": user.get("sub"), "role": user.get("role")}


# ── SYSTEM ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    return {
        "status":    "operational",
        "platform":  "NEXUS SPECTER PRO",
        "version":   "2.0.0-SPECTER",
        "company":   "OPTIMIUM NEXUS LLC",
        "timestamp": datetime.utcnow().isoformat(),
        "connections": len(ws_manager.active),
    }

@app.get("/", tags=["System"])
async def root():
    return {
        "platform": "NEXUS SPECTER PRO",
        "version":  "2.0.0-SPECTER",
        "company":  "OPTIMIUM NEXUS LLC",
        "tagline":  "Invisible. Inevitable. Unstoppable.",
        "docs":     "/docs",
    }


# ── WEBSOCKET ────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        await websocket.send_text(json.dumps({
            "event": "connected",
            "data":  {"message": "NSP WebSocket connected",
                      "platform": "NEXUS SPECTER PRO"},
            "ts":    datetime.utcnow().isoformat(),
        }))
        while True:
            msg = await websocket.receive_text()
            data = json.loads(msg)
            if data.get("type") == "ping":
                await websocket.send_text(json.dumps({"event": "pong"}))
            elif data.get("type") == "subscribe":
                mission_id = data.get("mission_id")
                await websocket.send_text(json.dumps({
                    "event": "subscribed",
                    "data": {"mission_id": mission_id},
                }))
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── MISSIONS ─────────────────────────────────────────────────────────────────
@app.get("/api/missions", tags=["Missions"])
async def list_missions(user: dict = Depends(verify_token)):
    return {"missions": list(DB["missions"].values()),
            "total": len(DB["missions"])}

@app.post("/api/missions", tags=["Missions"], status_code=201)
async def create_mission(req: MissionCreate, bt: BackgroundTasks,
                          user: dict = Depends(verify_token)):
    mid = f"NSP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
    mission = {
        "id":           mid,
        "name":         req.name,
        "target":       req.target,
        "mode":         req.mode,
        "phases":       req.phases,
        "ai_assist":    req.ai_assist,
        "status":       "queued",
        "progress":     0,
        "current_phase":"",
        "findings":     {"critical":0,"high":0,"medium":0,"low":0,"info":0},
        "created_at":   datetime.utcnow().isoformat(),
        "updated_at":   datetime.utcnow().isoformat(),
        "created_by":   user.get("sub","unknown"),
    }
    DB["missions"][mid] = mission
    bt.add_task(_run_mission, mid)
    await ws_manager.broadcast("mission_created", mission)
    return mission

async def _run_mission(mid: str):
    phases = ["recon","enumeration","vuln_scan","exploitation","post_exploit","reporting"]
    DB["missions"][mid]["status"] = "running"
    DB["missions"][mid]["started_at"] = datetime.utcnow().isoformat()
    await ws_manager.broadcast("mission_started", {"id": mid})
    for i, phase in enumerate(phases):
        await asyncio.sleep(3)
        DB["missions"][mid].update({
            "current_phase": phase,
            "progress":      int((i+1)/len(phases)*100),
            "updated_at":    datetime.utcnow().isoformat(),
        })
        await ws_manager.broadcast("mission_progress", {
            "id":      mid,
            "phase":   phase,
            "progress":DB["missions"][mid]["progress"],
        })
    DB["missions"][mid].update({
        "status":       "complete",
        "progress":     100,
        "completed_at": datetime.utcnow().isoformat(),
    })
    await ws_manager.broadcast("mission_complete", {"id": mid})

@app.get("/api/missions/{mid}", tags=["Missions"])
async def get_mission(mid: str, user: dict = Depends(verify_token)):
    if mid not in DB["missions"]:
        raise HTTPException(404, f"Mission {mid} not found")
    return DB["missions"][mid]

@app.patch("/api/missions/{mid}", tags=["Missions"])
async def update_mission(mid: str, payload: dict,
                          user: dict = Depends(verify_token)):
    if mid not in DB["missions"]:
        raise HTTPException(404, "Mission not found")
    DB["missions"][mid].update(payload)
    DB["missions"][mid]["updated_at"] = datetime.utcnow().isoformat()
    await ws_manager.broadcast("mission_updated", DB["missions"][mid])
    return DB["missions"][mid]

@app.delete("/api/missions/{mid}", tags=["Missions"])
async def delete_mission(mid: str, user: dict = Depends(verify_token)):
    if mid not in DB["missions"]:
        raise HTTPException(404, "Mission not found")
    del DB["missions"][mid]
    await ws_manager.broadcast("mission_deleted", {"id": mid})
    return {"status": "deleted", "id": mid}


# ── TARGETS ──────────────────────────────────────────────────────────────────
@app.get("/api/targets", tags=["Targets"])
async def list_targets(user: dict = Depends(verify_token)):
    return {"targets": list(DB["targets"].values()), "total": len(DB["targets"])}

@app.post("/api/targets", tags=["Targets"], status_code=201)
async def add_target(req: TargetCreate, user: dict = Depends(verify_token)):
    tid = str(uuid.uuid4())
    target = {**req.dict(), "id": tid, "added_at": datetime.utcnow().isoformat()}
    DB["targets"][tid] = target
    return target

@app.delete("/api/targets/{tid}", tags=["Targets"])
async def delete_target(tid: str, user: dict = Depends(verify_token)):
    if tid not in DB["targets"]:
        raise HTTPException(404, "Target not found")
    del DB["targets"][tid]
    return {"status": "deleted", "id": tid}


# ── RESULTS ──────────────────────────────────────────────────────────────────
@app.get("/api/results", tags=["Results"])
async def list_results(mission_id: str = None, severity: str = None,
                        user: dict = Depends(verify_token)):
    results = list(DB["results"].values())
    if mission_id:
        results = [r for r in results if r.get("mission_id") == mission_id]
    if severity:
        results = [r for r in results if r.get("severity") == severity]
    counts = {s: sum(1 for r in results if r.get("severity")==s)
              for s in ["critical","high","medium","low","info"]}
    return {"results": results, "total": len(results), "by_severity": counts}

@app.post("/api/results", tags=["Results"], status_code=201)
async def add_result(req: ResultCreate, user: dict = Depends(verify_token)):
    rid = str(uuid.uuid4())
    result = {**req.dict(), "id": rid, "found_at": datetime.utcnow().isoformat()}
    DB["results"][rid] = result
    # Update mission finding count
    mid = req.mission_id
    if mid in DB["missions"]:
        DB["missions"][mid]["findings"][req.severity] = \
            DB["missions"][mid]["findings"].get(req.severity, 0) + 1
    await ws_manager.broadcast("finding_added", result)
    return result

@app.get("/api/results/{rid}", tags=["Results"])
async def get_result(rid: str, user: dict = Depends(verify_token)):
    if rid not in DB["results"]:
        raise HTTPException(404, "Result not found")
    return DB["results"][rid]

@app.delete("/api/results/{rid}", tags=["Results"])
async def delete_result(rid: str, user: dict = Depends(verify_token)):
    if rid not in DB["results"]:
        raise HTTPException(404, "Result not found")
    del DB["results"][rid]
    return {"status": "deleted", "id": rid}


# ── STATS ────────────────────────────────────────────────────────────────────
@app.get("/api/stats", tags=["Dashboard"])
async def get_stats(user: dict = Depends(verify_token)):
    results  = list(DB["results"].values())
    missions = list(DB["missions"].values())
    return {
        "total_missions":  len(missions),
        "active_missions": len([m for m in missions if m.get("status")=="running"]),
        "complete_missions":len([m for m in missions if m.get("status")=="complete"]),
        "total_targets":   len(DB["targets"]),
        "total_findings":  len(results),
        "websocket_clients": len(ws_manager.active),
        "by_severity": {
            s: sum(1 for r in results if r.get("severity")==s)
            for s in ["critical","high","medium","low","info"]
        },
        "recent_missions": sorted(missions, key=lambda x: x.get("created_at",""),
                                   reverse=True)[:5],
        "platform": {"name":"NEXUS SPECTER PRO","version":"2.0.0-SPECTER",
                     "company":"OPTIMIUM NEXUS LLC"},
    }


# ── REPORTS ──────────────────────────────────────────────────────────────────
@app.post("/api/reports/generate", tags=["Reports"])
async def generate_report(payload: dict, bt: BackgroundTasks,
                           user: dict = Depends(verify_token)):
    bt.add_task(_generate_report, payload.get("mission_id"), payload.get("format","both"))
    return {"status":"generating","mission_id":payload.get("mission_id")}

async def _generate_report(mid: str, fmt: str):
    await asyncio.sleep(3)
    await ws_manager.broadcast("report_ready", {"mission_id": mid, "format": fmt})

@app.get("/api/reports", tags=["Reports"])
async def list_reports(user: dict = Depends(verify_token)):
    rdir = Path("./reports")
    reports = []
    if rdir.exists():
        for f in list(rdir.rglob("*.html")) + list(rdir.rglob("*.pdf")):
            reports.append({"filename":f.name,"path":str(f),
                             "size_kb":round(f.stat().st_size/1024,1),
                             "created_at":datetime.fromtimestamp(f.stat().st_ctime).isoformat()})
    return {"reports": reports, "total": len(reports)}


from pathlib import Path
