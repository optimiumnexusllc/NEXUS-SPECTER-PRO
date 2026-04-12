import { useState, useEffect, useCallback } from "react";

const API = "http://localhost:8080/api";

// ── Design tokens ──────────────────────────────────────────────────────────
const T = {
  purple: "#7B00FF", cyan: "#00FFD4", red: "#FF003C",
  orange: "#FF8C00", yellow: "#FFD700", dark: "#0A0A0A",
  card: "#0D0D0D", border: "#1E1E1E", muted: "#555",
  text: "#E8E8E8",
};
const SEV = {
  critical: { color: T.red,    bg: "rgba(255,0,60,0.12)"  },
  high:     { color: T.orange, bg: "rgba(255,140,0,0.12)" },
  medium:   { color: T.yellow, bg: "rgba(255,215,0,0.10)" },
  low:      { color: T.cyan,   bg: "rgba(0,255,212,0.10)" },
  info:     { color: T.muted,  bg: "rgba(85,85,85,0.08)"  },
};
const SEVERITIES = ["critical","high","medium","low","info"];

// ── Helpers ────────────────────────────────────────────────────────────────
const useFetch = (url, interval = 0) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const fetch_ = useCallback(async () => {
    try {
      const r = await fetch(url);
      if (r.ok) setData(await r.json());
    } catch {}
    setLoading(false);
  }, [url]);
  useEffect(() => {
    fetch_();
    if (interval) {
      const id = setInterval(fetch_, interval);
      return () => clearInterval(id);
    }
  }, [fetch_, interval]);
  return { data, loading, refetch: fetch_ };
};

// ── Mini Bar Chart (pure CSS) ──────────────────────────────────────────────
function BarChart({ data, height = 80 }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div style={{ display:"flex", alignItems:"flex-end", gap:6, height }}>
      {data.map((d, i) => (
        <div key={i} style={{ display:"flex", flexDirection:"column",
                               alignItems:"center", flex:1 }}>
          <div style={{ fontSize:9, color:T.muted, marginBottom:3 }}>{d.value}</div>
          <div style={{
            width:"100%", background: d.color || T.purple,
            height: `${(d.value/max)*100}%`, minHeight: d.value ? 4 : 0,
            borderRadius:"3px 3px 0 0",
            boxShadow: `0 0 8px ${d.color || T.purple}44`,
            transition: "height 0.6s ease",
          }} />
          <div style={{ fontSize:9, color:T.muted, marginTop:4,
                        textAlign:"center", lineHeight:1.2 }}>{d.label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Donut Chart (SVG) ──────────────────────────────────────────────────────
function DonutChart({ data, size = 100 }) {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const r = 38, cx = 50, cy = 50;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const slices = data.map(d => {
    const pct  = d.value / total;
    const dash = pct * circ;
    const slice = { color: d.color, dash, offset, label: d.label, value: d.value };
    offset += dash;
    return slice;
  });
  return (
    <svg width={size} height={size} viewBox="0 0 100 100">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1E1E1E" strokeWidth="14" />
      {slices.map((s, i) => s.value > 0 && (
        <circle key={i} cx={cx} cy={cy} r={r} fill="none"
          stroke={s.color} strokeWidth="14"
          strokeDasharray={`${s.dash} ${circ - s.dash}`}
          strokeDashoffset={circ / 4 - s.offset}
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
      ))}
      <text x="50" y="47" textAnchor="middle" fill={T.text}
            fontSize="16" fontWeight="900" fontFamily="monospace">
        {total}
      </text>
      <text x="50" y="58" textAnchor="middle" fill={T.muted}
            fontSize="7" fontFamily="monospace">
        TOTAL
      </text>
    </svg>
  );
}

// ── Severity Badge ─────────────────────────────────────────────────────────
function SevBadge({ sev, count, onClick }) {
  const s = SEV[sev] || SEV.info;
  return (
    <div onClick={onClick} style={{
      background: s.bg, border: `1px solid ${s.color}`,
      borderRadius: 8, padding: "16px 20px", textAlign: "center",
      minWidth: 100, cursor: onClick ? "pointer" : "default",
      transition: "all 0.2s", flex: 1,
    }}
    onMouseEnter={e => e.currentTarget.style.transform = "translateY(-2px)"}
    onMouseLeave={e => e.currentTarget.style.transform = "translateY(0)"}
    >
      <div style={{ fontSize: 34, fontWeight: 900, color: s.color,
                    fontFamily: "monospace" }}>{count}</div>
      <div style={{ fontSize: 10, color: T.muted, textTransform: "uppercase",
                    letterSpacing: 2, marginTop: 4 }}>{sev}</div>
    </div>
  );
}

// ── Progress Bar ───────────────────────────────────────────────────────────
function ProgressBar({ pct = 0, color = T.purple }) {
  return (
    <div style={{ background: "#111", borderRadius: 4, height: 5,
                  overflow: "hidden", flex: 1 }}>
      <div style={{
        width: `${pct}%`, height: "100%", borderRadius: 4,
        background: `linear-gradient(90deg, ${color}, ${T.cyan})`,
        transition: "width 0.6s ease",
        boxShadow: `0 0 6px ${color}66`,
      }} />
    </div>
  );
}

// ── Status Dot ────────────────────────────────────────────────────────────
function StatusDot({ status }) {
  const colors = { running: T.cyan, complete: T.purple,
                   queued: T.muted, failed: T.red };
  const c = colors[status] || T.muted;
  return (
    <span style={{
      display: "inline-block", width: 8, height: 8, borderRadius: "50%",
      background: c, marginRight: 8,
      boxShadow: status === "running" ? `0 0 8px ${c}` : "none",
      animation: status === "running" ? "pulse 1.5s infinite" : "none",
    }} />
  );
}

// ── Mission Row ────────────────────────────────────────────────────────────
function MissionRow({ mission }) {
  const f = mission.findings || {};
  return (
    <tr style={{ borderBottom: `1px solid ${T.border}`,
                 transition: "background 0.15s" }}
      onMouseEnter={e => e.currentTarget.style.background = "#0D0D1A"}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}
    >
      <td style={{ padding: "12px 16px", fontFamily: "monospace",
                   fontSize: 11, color: T.purple }}>
        {(mission.id || "").slice(-14)}
      </td>
      <td style={{ padding: "12px 16px", fontSize: 13 }}>{mission.target || "—"}</td>
      <td style={{ padding: "12px 16px", color: T.cyan, textTransform: "uppercase",
                   fontSize: 11, letterSpacing: 1 }}>{mission.mode}</td>
      <td style={{ padding: "12px 16px" }}>
        <StatusDot status={mission.status} />
        <span style={{ fontSize: 11, color:
          mission.status === "running" ? T.cyan :
          mission.status === "complete" ? T.purple : T.muted }}>
          {(mission.status || "").toUpperCase()}
        </span>
      </td>
      <td style={{ padding: "12px 16px", minWidth: 120 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <ProgressBar pct={mission.progress || 0} />
          <span style={{ fontSize: 10, color: T.muted, minWidth: 28 }}>
            {mission.progress || 0}%
          </span>
        </div>
      </td>
      <td style={{ padding: "12px 16px" }}>
        {SEVERITIES.slice(0,3).map(s => f[s] > 0 && (
          <span key={s} style={{ color: SEV[s].color, fontWeight: 700,
                                  marginRight: 10, fontSize: 12 }}>
            {f[s]}{s[0].toUpperCase()}
          </span>
        ))}
      </td>
    </tr>
  );
}

// ── New Mission Modal ──────────────────────────────────────────────────────
function MissionModal({ onClose, onSubmit }) {
  const [f, setF] = useState({
    name: "", target: "", mode: "black_box", phases: "all", ai_assist: true
  });
  const set = (k, v) => setF(p => ({ ...p, [k]: v }));
  const MODES = ["black_box","gray_box","white_box","red_team","cloud_audit"];

  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.85)",
                  display:"flex", alignItems:"center", justifyContent:"center",
                  zIndex:9999, backdropFilter:"blur(4px)" }}>
      <div style={{ background: T.card, border: `2px solid ${T.purple}`,
                    borderRadius: 12, padding: 40, minWidth: 500,
                    boxShadow: `0 0 80px ${T.purple}44` }}>
        <div style={{ color: T.purple, fontWeight: 900, fontSize: 18,
                      letterSpacing: 4, marginBottom: 28 }}>
          ⚡ NEW MISSION
        </div>

        {[["Mission Name","name"],["Target (domain / IP / CIDR)","target"]].map(([lbl,k]) => (
          <div key={k} style={{ marginBottom: 18 }}>
            <label style={{ color: T.cyan, fontSize: 10, letterSpacing: 2,
                            textTransform: "uppercase", display: "block", marginBottom: 6 }}>
              {lbl}
            </label>
            <input value={f[k]} onChange={e => set(k, e.target.value)}
              style={{ width: "100%", background: "#111", border: `1px solid ${T.border}`,
                       color: T.text, padding: "10px 14px", borderRadius: 6,
                       fontFamily: "monospace", outline: "none", fontSize: 13 }} />
          </div>
        ))}

        <div style={{ marginBottom: 18 }}>
          <label style={{ color: T.cyan, fontSize: 10, letterSpacing: 2,
                          textTransform: "uppercase", display: "block", marginBottom: 6 }}>
            Engagement Mode
          </label>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {MODES.map(m => (
              <button key={m} onClick={() => set("mode", m)} style={{
                padding: "7px 14px", borderRadius: 6, fontSize: 11,
                cursor: "pointer", fontFamily: "monospace", letterSpacing: 1,
                background: f.mode === m ? T.purple : "#111",
                color: f.mode === m ? "#fff" : T.muted,
                border: `1px solid ${f.mode === m ? T.purple : T.border}`,
                transition: "all 0.2s",
              }}>
                {m.replace(/_/g," ").toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: 24, display:"flex", alignItems:"center", gap:10 }}>
          <input type="checkbox" id="ai" checked={f.ai_assist}
            onChange={e => set("ai_assist", e.target.checked)}
            style={{ accentColor: T.purple }} />
          <label htmlFor="ai" style={{ color: T.cyan, fontSize: 13, cursor:"pointer" }}>
            🤖 Enable Specter AI (Anthropic Claude)
          </label>
        </div>

        <div style={{ display:"flex", gap:12 }}>
          <button onClick={() => onSubmit(f)} style={{
            flex:1, padding:"13px", background: T.purple, color:"#fff",
            border:"none", borderRadius:6, cursor:"pointer", fontWeight:900,
            fontSize:13, letterSpacing:3, fontFamily:"monospace",
            boxShadow:`0 0 20px ${T.purple}66`,
            transition:"all 0.2s",
          }}>
            ⚡ LAUNCH MISSION
          </button>
          <button onClick={onClose} style={{
            padding:"13px 20px", background:"transparent", color: T.muted,
            border:`1px solid ${T.border}`, borderRadius:6, cursor:"pointer",
          }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────────────────
export default function AppV2() {
  const [tab,   setTab]   = useState("dashboard");
  const [modal, setModal] = useState(false);
  const [filter, setFilter] = useState(null);

  const { data: stats,    loading: sl } = useFetch(`${API}/stats`,    5000);
  const { data: missions, loading: ml,
          refetch: reloadMissions }     = useFetch(`${API}/missions`,  5000);

  const sev  = stats?.by_severity || {};
  const mlist = missions?.missions || [];

  const launchMission = async (form) => {
    try {
      await fetch(`${API}/missions`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify(form)
      });
      setModal(false);
      reloadMissions();
    } catch(e) { console.error(e); }
  };

  // Chart data
  const barData = SEVERITIES.map(s => ({
    label: s.slice(0,4).toUpperCase(),
    value: sev[s] || 0,
    color: SEV[s].color,
  }));
  const donutData = SEVERITIES.filter(s => sev[s] > 0).map(s => ({
    label: s, value: sev[s] || 0, color: SEV[s].color,
  }));

  const NAV = ["dashboard","missions","results","reports","settings"];

  return (
    <div style={{ background: T.dark, minHeight:"100vh", color: T.text,
                  fontFamily:"'JetBrains Mono',monospace" }}>
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        ::-webkit-scrollbar{width:6px;height:6px}
        ::-webkit-scrollbar-track{background:#111}
        ::-webkit-scrollbar-thumb{background:#333;border-radius:3px}
        * { box-sizing: border-box; }
      `}</style>

      {modal && <MissionModal onClose={() => setModal(false)} onSubmit={launchMission} />}

      {/* TOPBAR */}
      <div style={{ background: T.card, borderBottom:`2px solid ${T.purple}`,
                    padding:"0 32px", display:"flex", alignItems:"center",
                    justifyContent:"space-between", height:58, position:"sticky",
                    top:0, zIndex:100 }}>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <span style={{ color: T.purple, fontWeight:900, fontSize:20, letterSpacing:5 }}>
            ⚡ NSP
          </span>
          <span style={{ color: T.cyan, fontSize:10, letterSpacing:3,
                         borderLeft:`1px solid ${T.border}`, paddingLeft:16 }}>
            NEXUS SPECTER PRO
          </span>
          <span style={{ color:"#222", fontSize:10 }}>|</span>
          <span style={{ color: T.muted, fontSize:10 }}>OPTIMIUM NEXUS LLC</span>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ width:8, height:8, borderRadius:"50%",
                           background: T.cyan, display:"inline-block",
                           boxShadow:`0 0 8px ${T.cyan}` }} />
            <span style={{ color: T.cyan, fontSize:10, letterSpacing:1 }}>OPERATIONAL</span>
          </div>
          <button onClick={() => setModal(true)} style={{
            background: T.purple, color:"#fff", border:"none", borderRadius:6,
            padding:"8px 20px", cursor:"pointer", fontWeight:900,
            fontSize:11, letterSpacing:2, fontFamily:"monospace",
            boxShadow:`0 0 16px ${T.purple}66`, transition:"all 0.2s",
          }}>
            + MISSION
          </button>
        </div>
      </div>

      {/* NAV */}
      <div style={{ background: T.card, borderBottom:`1px solid ${T.border}`,
                    padding:"0 32px", display:"flex", gap:2 }}>
        {NAV.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding:"13px 20px", background:"transparent",
            color: tab===t ? T.cyan : T.muted,
            border:"none",
            borderBottom: tab===t ? `2px solid ${T.cyan}` : "2px solid transparent",
            cursor:"pointer", fontSize:10, letterSpacing:2, textTransform:"uppercase",
            fontFamily:"monospace", transition:"all 0.2s",
          }}>
            {t}
          </button>
        ))}
      </div>

      <div style={{ padding:"28px 32px", maxWidth:1400, margin:"0 auto" }}>

        {/* ── DASHBOARD TAB ─────────────────────────────────────────────── */}
        {tab === "dashboard" && (
          <>
            {/* SEVERITY ROW */}
            <div style={{ display:"flex", gap:14, marginBottom:28, flexWrap:"wrap" }}>
              {SEVERITIES.map(s => (
                <SevBadge key={s} sev={s} count={sev[s]||0}
                  onClick={() => { setFilter(s); setTab("results"); }} />
              ))}
              <div style={{ background: T.card, border:`1px solid ${T.border}`,
                            borderRadius:8, padding:"16px 24px", textAlign:"center",
                            minWidth:100, flex:1 }}>
                <div style={{ fontSize:34, fontWeight:900, color: T.purple,
                              fontFamily:"monospace" }}>
                  {stats?.total_missions || 0}
                </div>
                <div style={{ fontSize:10, color: T.muted, textTransform:"uppercase",
                              letterSpacing:2, marginTop:4 }}>Missions</div>
              </div>
              <div style={{ background: T.card, border:`1px solid ${T.border}`,
                            borderRadius:8, padding:"16px 24px", textAlign:"center",
                            minWidth:100, flex:1 }}>
                <div style={{ fontSize:34, fontWeight:900, color: T.cyan,
                              fontFamily:"monospace" }}>
                  {stats?.total_findings || 0}
                </div>
                <div style={{ fontSize:10, color: T.muted, textTransform:"uppercase",
                              letterSpacing:2, marginTop:4 }}>Findings</div>
              </div>
            </div>

            {/* CHARTS ROW */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 2fr",
                          gap:16, marginBottom:28 }}>
              {/* Donut */}
              <div style={{ background: T.card, border:`1px solid ${T.border}`,
                            borderRadius:10, padding:24 }}>
                <div style={{ color: T.purple, fontWeight:700, fontSize:11,
                              letterSpacing:3, marginBottom:20 }}>SEVERITY SPLIT</div>
                <div style={{ display:"flex", alignItems:"center", gap:20 }}>
                  <DonutChart data={donutData.length ? donutData :
                    [{color:"#222", value:1, label:"none"}]} size={100} />
                  <div style={{ flex:1 }}>
                    {SEVERITIES.map(s => sev[s] > 0 && (
                      <div key={s} style={{ display:"flex", alignItems:"center",
                                            gap:8, marginBottom:6 }}>
                        <span style={{ width:8, height:8, borderRadius:"50%",
                                       background: SEV[s].color,
                                       display:"inline-block" }} />
                        <span style={{ fontSize:10, color: T.muted,
                                       textTransform:"uppercase" }}>{s}</span>
                        <span style={{ marginLeft:"auto", color: SEV[s].color,
                                       fontWeight:700, fontFamily:"monospace" }}>
                          {sev[s]||0}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Bar chart */}
              <div style={{ background: T.card, border:`1px solid ${T.border}`,
                            borderRadius:10, padding:24 }}>
                <div style={{ color: T.purple, fontWeight:700, fontSize:11,
                              letterSpacing:3, marginBottom:20 }}>FINDINGS BY SEVERITY</div>
                <BarChart data={barData} height={100} />
              </div>

              {/* Mission activity */}
              <div style={{ background: T.card, border:`1px solid ${T.border}`,
                            borderRadius:10, padding:24 }}>
                <div style={{ color: T.purple, fontWeight:700, fontSize:11,
                              letterSpacing:3, marginBottom:16 }}>ACTIVE MISSIONS</div>
                {mlist.slice(0,4).map(m => (
                  <div key={m.id} style={{ display:"flex", alignItems:"center",
                                            gap:12, marginBottom:14 }}>
                    <StatusDot status={m.status} />
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ fontSize:11, color: T.text, marginBottom:4,
                                    whiteSpace:"nowrap", overflow:"hidden",
                                    textOverflow:"ellipsis" }}>
                        {m.target || m.name || "—"}
                      </div>
                      <ProgressBar pct={m.progress||0} />
                    </div>
                    <span style={{ fontSize:10, color: T.muted, minWidth:30,
                                   textAlign:"right" }}>
                      {m.progress||0}%
                    </span>
                  </div>
                ))}
                {!mlist.length && (
                  <div style={{ color: T.muted, fontSize:12, textAlign:"center",
                                paddingTop:20 }}>
                    No missions — click <strong style={{color:T.purple}}>+ MISSION</strong>
                  </div>
                )}
              </div>
            </div>

            {/* MISSIONS TABLE */}
            <div style={{ background: T.card, border:`1px solid ${T.border}`,
                          borderRadius:10, overflow:"hidden" }}>
              <div style={{ padding:"16px 24px", borderBottom:`1px solid ${T.border}`,
                            display:"flex", justifyContent:"space-between",
                            alignItems:"center" }}>
                <span style={{ color: T.purple, fontWeight:700, fontSize:11,
                               letterSpacing:3 }}>
                  ⚡ MISSION LOG — {mlist.length}
                </span>
                <button onClick={() => setTab("missions")}
                  style={{ fontSize:10, color: T.cyan, background:"transparent",
                           border:`1px solid ${T.border}`, borderRadius:4,
                           padding:"4px 12px", cursor:"pointer", letterSpacing:1 }}>
                  VIEW ALL →
                </button>
              </div>
              <table style={{ width:"100%", borderCollapse:"collapse" }}>
                <thead>
                  <tr style={{ background:"#111" }}>
                    {["Session ID","Target","Mode","Status","Progress","Findings"].map(h => (
                      <th key={h} style={{ padding:"9px 16px", textAlign:"left",
                                           color: T.cyan, fontSize:9, letterSpacing:2,
                                           textTransform:"uppercase", fontWeight:600,
                                           borderBottom:`1px solid ${T.border}` }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {mlist.slice(0,8).map(m => <MissionRow key={m.id} mission={m} />)}
                  {!mlist.length && (
                    <tr><td colSpan={6} style={{ padding:40, textAlign:"center",
                                                  color: T.muted, fontSize:13 }}>
                      No missions yet. Click <strong style={{color:T.purple}}>+ MISSION</strong> to start.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {/* ── MISSIONS TAB ──────────────────────────────────────────────── */}
        {tab === "missions" && (
          <div style={{ background: T.card, border:`1px solid ${T.border}`,
                        borderRadius:10, overflow:"hidden" }}>
            <div style={{ padding:"16px 24px", borderBottom:`1px solid ${T.border}`,
                          display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ color: T.purple, fontWeight:700, fontSize:11, letterSpacing:3 }}>
                ALL MISSIONS — {mlist.length}
              </span>
              <button onClick={() => setModal(true)} style={{
                background: T.purple, color:"#fff", border:"none", borderRadius:6,
                padding:"7px 16px", cursor:"pointer", fontSize:10, letterSpacing:2,
                fontFamily:"monospace",
              }}>
                + NEW MISSION
              </button>
            </div>
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead>
                <tr style={{ background:"#111" }}>
                  {["Session ID","Target","Mode","Status","Progress","Findings"].map(h => (
                    <th key={h} style={{ padding:"9px 16px", textAlign:"left",
                                         color: T.cyan, fontSize:9, letterSpacing:2,
                                         textTransform:"uppercase",
                                         borderBottom:`1px solid ${T.border}` }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {mlist.map(m => <MissionRow key={m.id} mission={m} />)}
              </tbody>
            </table>
          </div>
        )}

        {/* ── PLACEHOLDER TABS ──────────────────────────────────────────── */}
        {["results","reports","settings"].includes(tab) && (
          <div style={{ textAlign:"center", paddingTop:80 }}>
            <div style={{ fontSize:52, marginBottom:16 }}>👻</div>
            <div style={{ color: T.purple, fontWeight:900, letterSpacing:6, fontSize:20 }}>
              {tab.toUpperCase()}
            </div>
            <div style={{ color: T.muted, marginTop:14, fontSize:13 }}>
              {tab === "results" && "Launch a mission to populate findings."}
              {tab === "reports" && "Generate a mission report to view PDF/HTML outputs."}
              {tab === "settings" && "Configure API keys, scan profiles, and notifications."}
            </div>
          </div>
        )}
      </div>

      {/* FOOTER */}
      <div style={{ borderTop:`1px solid ${T.border}`, padding:"14px 32px",
                    display:"flex", justifyContent:"space-between",
                    color: T.muted, fontSize:10, marginTop:40 }}>
        <span>NEXUS SPECTER PRO v1.0.0-SPECTER — by OPTIMIUM NEXUS LLC</span>
        <span>contact@optimiumnexus.com | www.optimiumnexus.com</span>
        <span style={{ color:"#333" }}>"Invisible. Inevitable. Unstoppable."</span>
      </div>
    </div>
  );
}
