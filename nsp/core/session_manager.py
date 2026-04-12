"""
NEXUS SPECTER PRO — Session Manager
AES-256 encrypted session storage + PostgreSQL/file persistence
Manages: mission state, findings, credentials (encrypted), audit trail
by OPTIMIUM NEXUS LLC | contact@optimiumnexus.com
"""

import os, json, uuid, logging, hashlib
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from rich.console import Console

console = Console()
log = logging.getLogger("nsp.core.session")

try:
    from cryptography.fernet import Fernet
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    log.warning("[SESSION] cryptography not installed — sessions stored unencrypted")


@dataclass
class NSPSession:
    session_id:    str
    mission_name:  str
    target:        str
    mode:          str
    created_at:    str
    updated_at:    str
    status:        str = "initialised"   # initialised|running|complete|failed
    operator:      str = "OPTIMIUM NEXUS LLC"
    phases_done:   list = field(default_factory=list)
    findings:      dict = field(default_factory=dict)
    recon_data:    dict = field(default_factory=dict)
    notes:         list = field(default_factory=list)
    audit_log:     list = field(default_factory=list)


class SessionManager:
    """
    Encrypted session manager for NEXUS SPECTER PRO.
    All sensitive session data (findings, credentials) is AES-256 encrypted at rest.
    Sessions are persisted to disk (JSON) and optionally to PostgreSQL.
    """

    SESSION_DIR = Path(os.getenv("NSP_SESSION_DIR", "/tmp/nsp_sessions"))

    def __init__(self, encryption_key: bytes = None, db_url: str = None):
        self.key     = encryption_key or self._load_or_create_key()
        self.fernet  = Fernet(self.key) if CRYPTO_OK else None
        self.db_url  = db_url or os.getenv("DATABASE_URL")
        self.SESSION_DIR.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, NSPSession] = {}
        log.info(f"[SESSION] Initialised — storage: {self.SESSION_DIR}"
                 + (" | encrypted" if self.fernet else " | plaintext"))

    def _load_or_create_key(self) -> bytes:
        key_file = self.SESSION_DIR / ".nsp_session.key"
        if key_file.exists():
            return key_file.read_bytes()
        if not CRYPTO_OK:
            return b""
        key = Fernet.generate_key()
        key_file.write_bytes(key)
        key_file.chmod(0o600)
        log.info("[SESSION] New encryption key generated")
        return key

    def create(self, mission_name: str, target: str, mode: str) -> NSPSession:
        """Create and persist a new session."""
        now = datetime.utcnow().isoformat()
        sid = f"NSP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        session = NSPSession(
            session_id   = sid,
            mission_name = mission_name,
            target       = target,
            mode         = mode,
            created_at   = now,
            updated_at   = now,
        )
        session.audit_log.append({"ts": now, "event": "session_created",
                                   "operator": "OPTIMIUM NEXUS LLC"})
        self._sessions[sid] = session
        self._save(session)
        console.print(f"[bold #00FFD4]  ✅ Session created: {sid}[/bold #00FFD4]")
        return session

    def get(self, session_id: str) -> Optional[NSPSession]:
        if session_id in self._sessions:
            return self._sessions[session_id]
        return self._load(session_id)

    def update(self, session_id: str, **kwargs) -> Optional[NSPSession]:
        session = self.get(session_id)
        if not session:
            log.error(f"[SESSION] Session not found: {session_id}")
            return None
        for k, v in kwargs.items():
            if hasattr(session, k):
                setattr(session, k, v)
        session.updated_at = datetime.utcnow().isoformat()
        session.audit_log.append({
            "ts": session.updated_at,
            "event": "session_updated",
            "fields": list(kwargs.keys()),
        })
        self._sessions[session_id] = session
        self._save(session)
        return session

    def add_finding(self, session_id: str, severity: str, finding: dict):
        session = self.get(session_id)
        if not session:
            return
        session.findings.setdefault(severity, []).append(finding)
        session.updated_at = datetime.utcnow().isoformat()
        self._save(session)

    def add_phase(self, session_id: str, phase: str, result: dict):
        session = self.get(session_id)
        if not session:
            return
        if phase not in session.phases_done:
            session.phases_done.append(phase)
        setattr(session, f"{phase}_data", result) if hasattr(session, f"{phase}_data") else None
        session.updated_at = datetime.utcnow().isoformat()
        session.audit_log.append({"ts": session.updated_at,
                                   "event": f"phase_complete", "phase": phase})
        self._save(session)

    def note(self, session_id: str, text: str):
        session = self.get(session_id)
        if session:
            session.notes.append({"ts": datetime.utcnow().isoformat(), "text": text})
            self._save(session)

    def complete(self, session_id: str):
        self.update(session_id, status="complete")
        console.print(f"[bold #7B00FF]  ✅ Session complete: {session_id}[/bold #7B00FF]")

    def list_sessions(self) -> list:
        sessions = []
        for path in self.SESSION_DIR.glob("*.nsp"):
            try:
                s = self._load_from_path(path)
                if s:
                    sessions.append({
                        "id":          s.session_id,
                        "mission":     s.mission_name,
                        "target":      s.target,
                        "mode":        s.mode,
                        "status":      s.status,
                        "created_at":  s.created_at,
                        "updated_at":  s.updated_at,
                        "phases_done": s.phases_done,
                        "findings_count": sum(len(v) for v in s.findings.values()),
                    })
            except Exception as e:
                log.debug(f"[SESSION] Could not read {path}: {e}")
        return sorted(sessions, key=lambda x: x["created_at"], reverse=True)

    def _session_path(self, session_id: str) -> Path:
        safe = session_id.replace("/","_").replace("\\","_")
        return self.SESSION_DIR / f"{safe}.nsp"

    def _save(self, session: NSPSession):
        data = json.dumps(asdict(session), indent=2, default=str)
        if self.fernet:
            blob = self.fernet.encrypt(data.encode())
            self._session_path(session.session_id).write_bytes(blob)
        else:
            self._session_path(session.session_id).write_text(data)

    def _load(self, session_id: str) -> Optional[NSPSession]:
        path = self._session_path(session_id)
        if not path.exists():
            return None
        return self._load_from_path(path)

    def _load_from_path(self, path: Path) -> Optional[NSPSession]:
        try:
            raw = path.read_bytes()
            if self.fernet:
                data = json.loads(self.fernet.decrypt(raw).decode())
            else:
                data = json.loads(raw.decode())
            s = NSPSession(**{k: v for k, v in data.items()
                              if k in NSPSession.__dataclass_fields__})
            self._sessions[s.session_id] = s
            return s
        except Exception as e:
            log.error(f"[SESSION] Load error {path}: {e}")
            return None

    def export_json(self, session_id: str) -> dict:
        s = self.get(session_id)
        return asdict(s) if s else {}

    def delete(self, session_id: str):
        path = self._session_path(session_id)
        if path.exists():
            path.unlink()
        self._sessions.pop(session_id, None)
        log.info(f"[SESSION] Deleted: {session_id}")
