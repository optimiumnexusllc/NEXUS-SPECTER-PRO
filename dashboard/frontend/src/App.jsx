import { useState, useEffect } from "react";

const API = "http://localhost:8080/api";

const SEV_COLOR = {
  critical: "#FF003C", high: "#FF8C00", medium: "#FFD700",
  low: "#00FFD4", info: "#888888"
};
const SEV_BG = {
  critical:"rgba(255,0,60,0.12)", high:"rgba(255,140,0,0.12)",
  medium:"rgba(255,215,0,0.10)", low:"rgba(0,255,212,0.10)", info:"rgba(136,136,136,0.08)"
};

function Badge({ sev, count }) {
  return (
    <div style={{
      background: SEV_BG[sev], border: `1px solid ${SEV_COLOR[sev]}`,
      borderRadius: 8, padding: "18px 24px", textAlign: "center", minWidth: 110
    }}>
      <div style={{ fontSize: 36, fontWeight: 900, color: SEV_COLOR[sev] }}>{count}</div>
      <div style={{ fontSize: 11, color: "#888", textTransform: "uppercase",
                    letterSpacing: 2, marginTop: 4 }}>{sev}</div>
    </div>
  );
}

function StatusDot({ status }) {
  const c = { running:"#00FFD4", complete:"#7B00FF", queued:"#888", failed:"#FF003C" };
  return <span style={{ display:"inline-block", width:8, height:8, borderRadius:"50%",
    background: c[status]||"#888", marginRight:8,
    boxShadow: status==="running" ? `0 0 8px ${c.running}` : "none" }} />;
}

function MissionRow({ mission }) {
  const f = mission.findings || {};
  return (
    <tr style={{ borderBottom:"1px solid #1E1E1E" }}>
      <td style={{ padding:"12px 16px", fontFamily:"monospace", fontSize:12, color:"#7B00FF" }}>
        {mission.id?.slice(-12)}
      </td>
      <td style={{ padding:"12px 16px" }}>{mission.target || "—"}</td>
      <td style={{ padding:"12px 16px", color:"#00FFD4", textTransform:"uppercase",
                   fontSize:12 }}>{mission.mode}</td>
      <td style={{ padding:"12px 16px" }}>
        <StatusDot status={mission.status} />
        <span style={{ fontSize:12, color: mission.status==="running"?"#00FFD4":
                       mission.status==="complete"?"#7B00FF":"#888" }}>
          {mission.status?.toUpperCase()}
        </span>
      </td>
      <td style={{ padding:"12px 16px" }}>
        <div style={{ background:"#111", borderRadius:4, height:6, overflow:"hidden" }}>
          <div style={{ width:`${mission.progress||0}%`, height:"100%",
            background:`linear-gradient(90deg,#7B00FF,#00FFD4)`,
            transition:"width 0.5s ease" }} />
        </div>
        <span style={{fontSize:10,color:"#555",marginTop:3,display:"block"}}>
          {mission.progress||0}%
        </span>
      </td>
      <td style={{ padding:"12px 16px" }}>
        {["critical","high","medium"].map(s => f[s] ? (
          <span key={s} style={{ color:SEV_COLOR[s], fontWeight:700,
                                  marginRight:8, fontSize:12 }}>
            {f[s]}{s[0].toUpperCase()}
          </span>
        ) : null)}
      </td>
    </tr>
  );
}

function NewMissionModal({ onClose, onSubmit }) {
  const [form, setForm] = useState({
    target:"", mode:"black_box", phases:"all", ai_assist:true, name:""
  });
  const set = (k,v) => setForm(f => ({...f,[k]:v}));
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.85)",
                  display:"flex", alignItems:"center", justifyContent:"center", zIndex:9999 }}>
      <div style={{ background:"#0A0A0A", border:"2px solid #7B00FF", borderRadius:12,
                    padding:40, minWidth:480, boxShadow:"0 0 60px rgba(123,0,255,0.4)" }}>
        <h2 style={{ color:"#7B00FF", marginBottom:24, fontSize:18, letterSpacing:3 }}>
          ⚡ NEW MISSION
        </h2>
        {[
          ["Mission Name", "name", "text"],
          ["Target (IP/Domain/CIDR)", "target", "text"],
        ].map(([label, key, type]) => (
          <div key={key} style={{ marginBottom:16 }}>
            <label style={{ color:"#00FFD4", fontSize:11, letterSpacing:2,
                            textTransform:"uppercase", display:"block", marginBottom:6 }}>
              {label}
            </label>
            <input type={type} value={form[key]}
              onChange={e => set(key, e.target.value)}
              style={{ width:"100%", background:"#111", border:"1px solid #1E1E1E",
                       color:"#E8E8E8", padding:"10px 14px", borderRadius:6,
                       fontFamily:"monospace", outline:"none", fontSize:13 }} />
          </div>
        ))}
        <div style={{ marginBottom:16 }}>
          <label style={{ color:"#00FFD4", fontSize:11, letterSpacing:2,
                          textTransform:"uppercase", display:"block", marginBottom:6 }}>
            Mode
          </label>
          <select value={form.mode} onChange={e => set("mode", e.target.value)}
            style={{ width:"100%", background:"#111", border:"1px solid #1E1E1E",
                     color:"#E8E8E8", padding:"10px 14px", borderRadius:6, fontSize:13 }}>
            {["black_box","gray_box","white_box","red_team","cloud_audit"].map(m => (
              <option key={m} value={m}>{m.replace("_"," ").toUpperCase()}</option>
            ))}
          </select>
        </div>
        <div style={{ marginBottom:24, display:"flex", alignItems:"center", gap:10 }}>
          <input type="checkbox" id="ai" checked={form.ai_assist}
            onChange={e => set("ai_assist", e.target.checked)} />
          <label htmlFor="ai" style={{ color:"#00FFD4", fontSize:13 }}>
            🤖 Enable Specter AI (Claude API)
          </label>
        </div>
        <div style={{ display:"flex", gap:12 }}>
          <button onClick={() => onSubmit(form)}
            style={{ flex:1, padding:"12px", background:"#7B00FF", color:"#fff",
                     border:"none", borderRadius:6, cursor:"pointer", fontWeight:700,
                     fontSize:14, letterSpacing:2 }}>
            ⚡ LAUNCH MISSION
          </button>
          <button onClick={onClose}
            style={{ padding:"12px 20px", background:"transparent", color:"#888",
                     border:"1px solid #333", borderRadius:6, cursor:"pointer" }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [stats,    setStats]    = useState(null);
  const [missions, setMissions] = useState([]);
  const [modal,    setModal]    = useState(false);
  const [tab,      setTab]      = useState("dashboard");

  const load = async () => {
    try {
      const [s, m] = await Promise.all([
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/missions`).then(r => r.json()),
      ]);
      setStats(s);
      setMissions(m.missions || []);
    } catch {}
  };

  useEffect(() => { load(); const i = setInterval(load, 5000); return () => clearInterval(i); }, []);

  const launchMission = async (form) => {
    await fetch(`${API}/missions`, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify(form)
    });
    setModal(false);
    load();
  };

  const sev = stats?.by_severity || {};

  return (
    <div style={{ background:"#0A0A0A", minHeight:"100vh", color:"#E8E8E8",
                  fontFamily:"'JetBrains Mono',monospace" }}>
      {modal && <NewMissionModal onClose={() => setModal(false)} onSubmit={launchMission} />}

      {/* TOPBAR */}
      <div style={{ background:"#0D0D0D", borderBottom:"2px solid #7B00FF",
                    padding:"0 32px", display:"flex", alignItems:"center",
                    justifyContent:"space-between", height:60 }}>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <span style={{ color:"#7B00FF", fontWeight:900, fontSize:18, letterSpacing:4 }}>
            ⚡ NSP
          </span>
          <span style={{ color:"#00FFD4", fontSize:11, letterSpacing:2 }}>
            NEXUS SPECTER PRO
          </span>
          <span style={{ color:"#333", fontSize:11 }}>|</span>
          <span style={{ color:"#555", fontSize:11 }}>by OPTIMIUM NEXUS LLC</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <span style={{ width:8, height:8, borderRadius:"50%", background:"#00FFD4",
                         display:"inline-block", boxShadow:"0 0 8px #00FFD4" }} />
          <span style={{ color:"#00FFD4", fontSize:11 }}>OPERATIONAL</span>
          <button onClick={() => setModal(true)}
            style={{ background:"#7B00FF", color:"#fff", border:"none", borderRadius:6,
                     padding:"8px 20px", cursor:"pointer", fontWeight:700,
                     fontSize:12, letterSpacing:2 }}>
            + NEW MISSION
          </button>
        </div>
      </div>

      {/* NAV */}
      <div style={{ background:"#0D0D0D", borderBottom:"1px solid #1E1E1E",
                    padding:"0 32px", display:"flex", gap:4 }}>
        {["dashboard","missions","results","reports"].map(t => (
          <button key={t} onClick={() => setTab(t)}
            style={{ padding:"14px 20px", background:"transparent",
                     color: tab===t ? "#00FFD4" : "#555",
                     border:"none", borderBottom: tab===t ? "2px solid #00FFD4" : "2px solid transparent",
                     cursor:"pointer", fontSize:12, letterSpacing:2, textTransform:"uppercase" }}>
            {t}
          </button>
        ))}
      </div>

      <div style={{ padding:32 }}>
        {tab === "dashboard" && (
          <>
            {/* SEVERITY BADGES */}
            <div style={{ display:"flex", gap:16, marginBottom:32, flexWrap:"wrap" }}>
              {["critical","high","medium","low","info"].map(s => (
                <Badge key={s} sev={s} count={sev[s]||0} />
              ))}
              <div style={{ marginLeft:"auto", background:"#111", border:"1px solid #1E1E1E",
                            borderRadius:8, padding:"18px 24px", textAlign:"center" }}>
                <div style={{ fontSize:36, fontWeight:900, color:"#7B00FF" }}>
                  {stats?.total_missions||0}
                </div>
                <div style={{ fontSize:11, color:"#888", textTransform:"uppercase",
                              letterSpacing:2, marginTop:4 }}>Missions</div>
              </div>
              <div style={{ background:"#111", border:"1px solid #1E1E1E",
                            borderRadius:8, padding:"18px 24px", textAlign:"center" }}>
                <div style={{ fontSize:36, fontWeight:900, color:"#00FFD4" }}>
                  {stats?.total_findings||0}
                </div>
                <div style={{ fontSize:11, color:"#888", textTransform:"uppercase",
                              letterSpacing:2, marginTop:4 }}>Total Findings</div>
              </div>
            </div>

            {/* RECENT MISSIONS */}
            <div style={{ background:"#0D0D0D", border:"1px solid #1E1E1E",
                          borderRadius:10, overflow:"hidden" }}>
              <div style={{ padding:"18px 24px", borderBottom:"1px solid #1E1E1E",
                            color:"#7B00FF", fontWeight:700, letterSpacing:3, fontSize:13 }}>
                ⚡ RECENT MISSIONS
              </div>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead>
                  <tr style={{ background:"#111" }}>
                    {["Session ID","Target","Mode","Status","Progress","Findings"].map(h => (
                      <th key={h} style={{ padding:"10px 16px", textAlign:"left",
                                           color:"#00FFD4", fontSize:11, letterSpacing:2,
                                           textTransform:"uppercase", fontWeight:600 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {missions.slice(0,10).map(m => <MissionRow key={m.id} mission={m} />)}
                  {!missions.length && (
                    <tr><td colSpan={6} style={{ padding:40, textAlign:"center", color:"#333" }}>
                      No missions yet — click <strong style={{color:"#7B00FF"}}>+ NEW MISSION</strong>
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {tab === "missions" && (
          <div style={{ background:"#0D0D0D", border:"1px solid #1E1E1E",
                        borderRadius:10, overflow:"hidden" }}>
            <div style={{ padding:"18px 24px", borderBottom:"1px solid #1E1E1E",
                          display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ color:"#7B00FF", fontWeight:700, letterSpacing:3, fontSize:13 }}>
                ALL MISSIONS — {missions.length}
              </span>
              <button onClick={() => setModal(true)}
                style={{ background:"#7B00FF", color:"#fff", border:"none", borderRadius:6,
                         padding:"8px 16px", cursor:"pointer", fontSize:12, letterSpacing:2 }}>
                + NEW
              </button>
            </div>
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead>
                <tr style={{ background:"#111" }}>
                  {["Session ID","Target","Mode","Status","Progress","Findings"].map(h => (
                    <th key={h} style={{ padding:"10px 16px", textAlign:"left",
                                         color:"#00FFD4", fontSize:11, letterSpacing:2,
                                         textTransform:"uppercase", fontWeight:600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {missions.map(m => <MissionRow key={m.id} mission={m} />)}
              </tbody>
            </table>
          </div>
        )}

        {(tab === "results" || tab === "reports") && (
          <div style={{ color:"#555", textAlign:"center", marginTop:80, fontSize:14 }}>
            <div style={{ fontSize:48, marginBottom:16 }}>👻</div>
            <div style={{ color:"#7B00FF", fontWeight:700, letterSpacing:4, fontSize:18 }}>
              {tab.toUpperCase()} MODULE
            </div>
            <div style={{ marginTop:12 }}>Launch a mission to populate {tab}.</div>
          </div>
        )}
      </div>

      {/* FOOTER */}
      <div style={{ borderTop:"1px solid #1E1E1E", padding:"16px 32px",
                    display:"flex", justifyContent:"space-between", color:"#333", fontSize:11 }}>
        <span>NEXUS SPECTER PRO v1.0.0-SPECTER — by OPTIMIUM NEXUS LLC</span>
        <span>contact@optimiumnexus.com | www.optimiumnexus.com</span>
        <span>"Invisible. Inevitable. Unstoppable."</span>
      </div>
    </div>
  );
}
