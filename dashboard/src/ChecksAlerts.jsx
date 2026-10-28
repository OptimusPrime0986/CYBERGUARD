import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import { Badge } from "./charts.jsx";
import { Errors, when } from "./Overview.jsx";

const ST = { pass: ["ok", "Pass"], fail: ["bad", "Fail"], warn: ["warn", "Warning"], info: ["neutral", "Info"] };

export function Checks({ id, user }) {
  const [r, setR] = useState(null), [err, setErr] = useState(null), [busy, setBusy] = useState(false);
  useEffect(() => { api("GET", `/sites/${id}/scan`).then(setR).catch(setErr); }, [id]);
  const run = async () => { setBusy(true); setErr(null); try { setR(await api("POST", `/sites/${id}/scan`)); } catch (x) { setErr(x); } finally { setBusy(false); } };
  const order = ["fail", "warn", "pass", "info"];
  return (<div className="card"><div className="row between"><h2>Security checks</h2>{user.role !== "analyst" && <button className="primary" disabled={busy} onClick={run}>{busy ? "Scanning…" : "Run scan now"}</button>}</div>
    <p className="muted">Checks how this site is <b>configured</b> (headers, exposed files, HTTPS, firewall settings). These are configuration findings, separate from attacks detected in Events. The scan sends a few harmless GET requests through the proxy.</p><Errors err={err} />
    {r?.error && <div className="alert warn">{r.error}</div>}
    {!r?.findings ? <p className="muted">No scan has been run yet.</p> : <>
      <p>{["fail", "warn", "pass"].map((k) => <Badge key={k} cls={ST[k][0]}>{r.summary[k] || 0} {ST[k][1].toLowerCase()}</Badge>)} <span className="small">last scan {when(r.ts)}</span></p>
      {[...r.findings].sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status)).map((f) => <div key={f.id} className="finding"><div><Badge cls={ST[f.status][0]}>{ST[f.status][1]}</Badge><div className="small">{f.owasp}</div></div>
        <div><b>{f.title}</b> <span className="small">({f.severity})</span><div>{f.detail}</div>{f.fix && <div className="fix">Fix: {f.fix}</div>}</div></div>)}</>}</div>);
}

const KINDS = { high_severity: "Critical/high firewall detections", blocked_spike: "Blocked requests spike", rate_limit: "Rate-limited requests", origin_errors: "Website server errors (5xx)", protection_reduced: "Protection reduced (blocking → monitoring/disabled)", deploy_failed: "A policy change failed", pipeline: "Event pipeline stalled or failing" };

export function Alerts({ id, user }) {
  const [c, setC] = useState(null), [hist, setHist] = useState([]), [err, setErr] = useState(null), [msg, setMsg] = useState(null), [busy, setBusy] = useState(false);
  const dis = user.role === "analyst";
  const load = () => Promise.all([api("GET", `/sites/${id}/alerts`), api("GET", `/sites/${id}/notifications`)]).then(([a, h]) => { setC(a); setHist(h); }).catch(setErr);
  useEffect(() => { load(); }, [id]);
  if (!c) return err ? <Errors err={err} /> : <p>Loading…</p>;
  const kind = (k, patch) => setC({ ...c, kinds: { ...c.kinds, [k]: { ...c.kinds[k], ...patch } } });
  const go = async (fn, ok) => { setBusy(true); setErr(null); setMsg(null); try { await fn(); setMsg(ok); await load(); } catch (x) { setErr(x); } finally { setBusy(false); } };
  return (<div><Errors err={err} />{msg && <div className="alert ok">{msg}</div>}
    <div className="card"><h2>Email alerts</h2>
      <label className="check"><input type="checkbox" disabled={dis} checked={c.enabled} onChange={(e) => setC({ ...c, enabled: e.target.checked })} />Send alerts for this website</label>
      <div className="row"><label>Send to<input type="email" disabled={dis} value={c.email} onChange={(e) => setC({ ...c, email: e.target.value })} placeholder="ops@example.com" /></label>
        <label>Cooldown (minutes between repeats)<input type="number" disabled={dis} value={c.cooldown_minutes} onChange={(e) => setC({ ...c, cooldown_minutes: parseInt(e.target.value || 15, 10) })} /></label></div>
      {Object.entries(KINDS).map(([k, label]) => <div key={k} className="row" style={{ alignItems: "center" }}>
        <label className="check" style={{ flex: "2 1 260px" }}><input type="checkbox" disabled={dis} checked={c.kinds[k].on} onChange={(e) => kind(k, { on: e.target.checked })} />{label}</label>
        {"threshold" in c.kinds[k] && <label style={{ margin: 0 }}>when ≥ <input type="number" style={{ width: 90, display: "inline" }} disabled={dis} value={c.kinds[k].threshold} onChange={(e) => kind(k, { threshold: parseInt(e.target.value || 1, 10) })} /> in 5 min</label>}</div>)}
      <p className="small">Alerts contain counts and site names only, never request content. Repeats are suppressed during the cooldown. Delivery is best-effort: failures are recorded below, not hidden. The demo setup sends to a local inbox at <a href="http://127.0.0.1:8025" target="_blank" rel="noreferrer">127.0.0.1:8025</a>.</p>
      {!dis && <div className="row"><button className="primary" disabled={busy} onClick={() => go(() => api("PUT", `/sites/${id}/alerts`, c), "Alert settings saved.")}>Save</button>
        <button disabled={busy} onClick={() => go(async () => { const r = await api("POST", `/sites/${id}/alerts/test`); if (!r.sent) throw Object.assign(new Error("Test email failed: " + (r.notifications[0]?.error || "unknown")), {}); }, "Test email sent.")}>Send test email</button></div>}</div>
    <div className="card"><h2>Delivery history</h2>{hist.length === 0 ? <p className="muted">No alerts sent yet.</p> :
      <table><thead><tr><th>When</th><th>Kind</th><th>To</th><th>Status</th><th>Detail</th></tr></thead><tbody>{hist.map((h) => <tr key={h.id}><td>{when(h.ts)}</td><td>{h.kind}</td><td>{h.destination}</td><td><Badge cls={h.status === "sent" ? "ok" : "bad"}>{h.status}</Badge></td><td>{h.error || h.summary}</td></tr>)}</tbody></table>}</div></div>);
}
