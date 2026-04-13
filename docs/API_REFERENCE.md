# NEXUS SPECTER PRO — API Reference
**by OPTIMIUM NEXUS LLC** | v2.0.0-SPECTER | contact@optimiumnexus.com

Base URL: `http://localhost:8080`
Interactive docs: `http://localhost:8080/docs` (Swagger UI)

---

## Authentication

All API endpoints (except `/health`, `/`, `/api/auth/login`) require a JWT Bearer token.

### POST /api/auth/login

Obtain an access token.

**Request:**
```json
{ "username": "admin", "password": "your_password" }
```

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type":   "bearer",
  "expires_in":   86400,
  "username":     "admin",
  "role":         "admin"
}
```

Use the token in subsequent requests:
```
Authorization: Bearer <access_token>
```

---

## System

### GET /health

Returns platform health status. No auth required.

```json
{
  "status":      "operational",
  "platform":    "NEXUS SPECTER PRO",
  "version":     "2.0.0-SPECTER",
  "company":     "OPTIMIUM NEXUS LLC",
  "timestamp":   "2025-04-13T12:00:00",
  "connections": 3
}
```

### GET /api/auth/me

Returns current authenticated user info.

```json
{ "username": "admin", "role": "admin" }
```

---

## WebSocket

### WS /ws

Real-time event stream for live mission monitoring.

**Connect:** `ws://localhost:8080/ws`

**Events received:**

| Event | Payload | Description |
|-------|---------|-------------|
| `connected` | `{message}` | Connection established |
| `mission_created` | Mission object | New mission queued |
| `mission_started` | `{id}` | Mission execution started |
| `mission_progress` | `{id, phase, progress}` | Phase completion update |
| `mission_complete` | `{id}` | All phases done |
| `finding_added` | Result object | New vulnerability found |
| `report_ready` | `{mission_id, format}` | Report generation done |

**Client → Server messages:**
```json
{ "type": "ping" }
{ "type": "subscribe", "mission_id": "NSP-20250413-ABCDEF" }
```

**JavaScript example:**
```javascript
const ws = new WebSocket("ws://localhost:8080/ws");
ws.onmessage = (e) => {
  const { event, data } = JSON.parse(e.data);
  if (event === "mission_progress") {
    console.log(`Phase: ${data.phase} | ${data.progress}%`);
  }
};
```

---

## Missions

### GET /api/missions

List all missions.

**Response:**
```json
{
  "missions": [
    {
      "id":           "NSP-20250413-AB1C2D",
      "name":         "Client Corp External Assessment",
      "target":       "example.com",
      "mode":         "black_box",
      "status":       "complete",
      "progress":     100,
      "current_phase":"",
      "findings":     {"critical":2,"high":5,"medium":12,"low":8,"info":30},
      "created_at":   "2025-04-13T09:00:00",
      "updated_at":   "2025-04-13T11:30:00",
      "created_by":   "admin"
    }
  ],
  "total": 1
}
```

### POST /api/missions

Create and launch a new mission.

**Request:**
```json
{
  "name":      "External Black Box — Example Corp",
  "target":    "example.com",
  "mode":      "black_box",
  "phases":    "all",
  "ai_assist": true
}
```

**Mode options:** `black_box` | `gray_box` | `white_box` | `red_team` | `cloud_audit`

**Response:** `201 Created` — Mission object with ID.

### GET /api/missions/{id}

Get a specific mission by ID.

**Response:** Mission object or `404 Not Found`.

### PATCH /api/missions/{id}

Update mission fields.

**Request:** Any mission fields to update.

### DELETE /api/missions/{id}

Delete a mission. Returns `{"status": "deleted", "id": "..."}`.

---

## Targets

### GET /api/targets

List all registered targets.

```json
{
  "targets": [
    {
      "id":       "550e8400-e29b-41d4-a716-446655440000",
      "host":     "example.com",
      "type":     "domain",
      "scope":    "in",
      "notes":    "Primary web application",
      "tags":     ["web","external"],
      "added_at": "2025-04-13T08:00:00"
    }
  ],
  "total": 1
}
```

### POST /api/targets

Add a target to the registry.

**Request:**
```json
{
  "host":  "example.com",
  "type":  "domain",
  "scope": "in",
  "notes": "Primary web application",
  "tags":  ["web", "external"]
}
```

**Type options:** `domain` | `ip` | `cidr` | `url`
**Scope options:** `in` | `out`

### DELETE /api/targets/{id}

Remove a target from the registry.

---

## Results (Findings)

### GET /api/results

List findings, optionally filtered.

**Query params:**
- `mission_id` — Filter by mission
- `severity` — Filter by severity (`critical|high|medium|low|info`)

**Response:**
```json
{
  "results": [
    {
      "id":          "uuid",
      "mission_id":  "NSP-20250413-AB1C2D",
      "name":        "SQL Injection in /api/users",
      "severity":    "critical",
      "host":        "api.example.com",
      "port":        443,
      "description": "The `id` parameter is vulnerable to SQL injection...",
      "evidence":    "' OR 1=1-- response: 200 OK, 5432 bytes",
      "cvss":        9.8,
      "cve":         "N/A",
      "cwe":         "CWE-89",
      "remediation": "Use parameterized queries...",
      "tool":        "nuclei",
      "mitre":       "T1190",
      "tags":        ["sqli","injection","critical"],
      "found_at":    "2025-04-13T10:15:00"
    }
  ],
  "total": 1,
  "by_severity": {
    "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0
  }
}
```

### POST /api/results

Add a finding (used by scan modules internally or via API).

**Request:**
```json
{
  "mission_id":  "NSP-20250413-AB1C2D",
  "name":        "SQL Injection in /api/users",
  "severity":    "critical",
  "host":        "api.example.com",
  "port":        443,
  "description": "The id parameter is injectable.",
  "evidence":    "' OR 1=1-- returns 200",
  "cvss":        9.8,
  "cve":         "",
  "cwe":         "CWE-89",
  "remediation": "Use parameterized queries.",
  "tool":        "nuclei",
  "mitre":       "T1190",
  "tags":        ["sqli"]
}
```

### GET /api/results/{id}

Get a specific result.

### DELETE /api/results/{id}

Delete a result.

---

## Reports

### GET /api/reports

List generated report files.

```json
{
  "reports": [
    {
      "filename":   "NSP-20250413-AB1C2D_executive.html",
      "path":       "reports/NSP-20250413-AB1C2D_executive.html",
      "size_kb":    284.5,
      "created_at": "2025-04-13T11:30:00"
    }
  ],
  "total": 2
}
```

### POST /api/reports/generate

Trigger report generation for a mission.

**Request:**
```json
{
  "mission_id": "NSP-20250413-AB1C2D",
  "format":     "both"
}
```

**Format options:** `html` | `pdf` | `both` | `json`

**Response:** `{"status": "generating", "mission_id": "..."}` — subscribe to WebSocket for completion event.

---

## Stats / Dashboard

### GET /api/stats

Aggregated platform statistics.

```json
{
  "total_missions":    12,
  "active_missions":   2,
  "complete_missions": 10,
  "total_targets":     45,
  "total_findings":    234,
  "websocket_clients": 3,
  "by_severity": {
    "critical": 8,
    "high":     42,
    "medium":   98,
    "low":      64,
    "info":     22
  },
  "recent_missions": [...],
  "platform": {
    "name":    "NEXUS SPECTER PRO",
    "version": "2.0.0-SPECTER",
    "company": "OPTIMIUM NEXUS LLC"
  }
}
```

---

## Error Responses

All errors follow this format:

```json
{ "detail": "Error message here" }
```

| Code | Meaning |
|------|---------|
| `400` | Bad request — invalid input |
| `401` | Unauthorized — missing or invalid token |
| `403` | Forbidden — insufficient role |
| `404` | Not found |
| `422` | Validation error — check request body |
| `500` | Internal server error |

---

## SDK Usage (Python)

```python
import httpx

BASE = "http://localhost:8080"

# Login
r = httpx.post(f"{BASE}/api/auth/login",
               json={"username":"admin","password":"nsp_admin_2025!"})
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# Create mission
mission = httpx.post(f"{BASE}/api/missions", headers=headers, json={
    "name":   "My Assessment",
    "target": "example.com",
    "mode":   "black_box",
}).json()
print(f"Mission ID: {mission['id']}")

# Poll status
import time
while True:
    m = httpx.get(f"{BASE}/api/missions/{mission['id']}", headers=headers).json()
    print(f"Status: {m['status']} | Progress: {m['progress']}%")
    if m["status"] in ("complete","failed"):
        break
    time.sleep(5)

# Get findings
findings = httpx.get(f"{BASE}/api/results",
                     headers=headers,
                     params={"mission_id": mission["id"]}).json()
print(f"Total findings: {findings['total']}")
for sev, count in findings["by_severity"].items():
    print(f"  {sev}: {count}")
```

---

*NEXUS SPECTER PRO v2.0.0-SPECTER — by OPTIMIUM NEXUS LLC*
*contact@optimiumnexus.com | www.optimiumnexus.com*
