import React, { useCallback, useEffect, useState } from "react";
import { api } from "./api.js";
import { useLive } from "./hooks.js";
import { Bars, HBars, Stat, Badge, SEV, n } from "./charts.jsx";
import { IconBack } from "./icons.jsx";
import { MODE, SYNC, Errors, when, RangeBar } from "./Overview.jsx";
import PolicyTab from "./PolicyTab.jsx";
import { Checks, Alerts } from "./ChecksAlerts.jsx";

function Confirm({ site, onYes, onNo, busy }) {
  return (<div className="modal" role="dialog" aria-modal="true"><div className="card"><h2>Disable protection for “{site.name}”?</h2>
    <div className="alert bad">The firewall will stop inspecting and blocking attacks on <b>{site.hostname}</b>. Other websites are not affected.</div>
    <div className="row"><button onClick={onNo}>Cancel</button><button className="danger" disabled={busy} onClick={onYes}>{busy ? "Applying…" : "Yes, disable protection"}</button></div></div></div>);
}

function EventModal({ e, onClose }) {
  const Row = ({ k, v }) => <tr><th>{k}</th><td>{v ?? "—"}</td></tr>;
  const blocked = e.event_type === "blocked";
  return (<div className="modal" onClick={onClose}><div className="card wide" onClick={(x) => x.stopPropagation()}>
    <div className="row between"><h2>Security event</h2><button onClick={onClose}>Close</button></div>
    <div className={`alert ${blocked ? "ok" : "warn"}`}>{blocked ? "This request was BLOCKED by the firewall and did not reach the website." :
      `This request was DETECTED but ALLOWED through${e.mode && e.mode !== "blocking" ? ` (site was in “${e.mode}” mode)` : ""}. It reached the website.`}</div>
    <table><tbody>
      <Row k="Time" v={when(e.ts)} /><Row k="Rule" v={<><code>{e.rule_id}</code> — {e.message}</>} /><Row k="Severity" v={<Badge cls={SEV[e.severity]}>{e.severity}</Badge>} />
      <Row k="Category" v={e.category} /><Row k="Anomaly score" v={e.score} /><Row k="Other rules matched" v={e.rule_ids.filter((r) => r !== e.rule_id).join(", ") || "—"} />
      <Row k="Request" v={<code>{e.method} {e.path}{e.query ? "?" + e.query : ""}</code>} /><Row k="Matched data" v={e.data && <code>{e.data}</code>} />
      <Row k="Response status" v={e.status} /><Row k="Client IP" v={e.client_ip} /><Row k="User agent" v={e.user_agent} />
      <Row k="Policy version" v={e.policy_version ? `v${e.policy_version}` : "unknown"} /><Row k="Event id" v={<code>{e.id}</code>} /></tbody></table>
    <p className="muted">Sensitive query values are redacted; request bodies are never stored.</p></div></div>);
}

function Events({ id }) {
  const [f, setF] = useState({ type: "", severity: "", rule_id: "", q: "" }), [applied, setApplied] = useState(f), [page, setPage] = useState(0), [sel, setSel] = useState(null);
  const qs = () => new URLSearchParams({ ...Object.fromEntries(Object.entries(applied).filter(([, v]) => v)), limit: 15, offset: page * 15 }).toString();
  const [d, err] = useLive(() => api("GET", `/sites/${id}/events?${qs()}`), [id, applied, page], true);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  return (<div className="card"><h2>Security events</h2>
    <div className="row filters">
      <select value={f.type} onChange={set("type")}><option value="">All actions</option><option value="blocked">Blocked</option><option value="detected">Detected only</option></select>
      <select value={f.severity} onChange={set("severity")}><option value="">All severities</option>{["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select>
      <input placeholder="Rule id (e.g. 942100)" value={f.rule_id} onChange={set("rule_id")} /><input placeholder="Search path / message" value={f.q} onChange={set("q")} />
      <button className="primary" onClick={() => { setPage(0); setApplied(f); }}>Apply</button></div>
    <Errors err={err} />{!d ? "Loading…" : d.items.length === 0 ? <p className="muted">No events match. (Events appear when the firewall matches a rule; normal traffic creates none.)</p> :
      <div className="scroll"><table className="click"><thead><tr><th>Time</th><th>Action</th><th>Severity</th><th>Rule</th><th>Request</th></tr></thead><tbody>
        {d.items.map((e) => <tr key={e.id} onClick={() => setSel(e)}><td>{when(e.ts)}</td><td><Badge cls={e.event_type === "blocked" ? "bad" : "warn"}>{e.event_type}</Badge></td>
          <td><Badge cls={SEV[e.severity]}>{e.severity}</Badge></td><td><code>{e.rule_id}</code><div className="muted">{e.message}</div></td><td><code>{e.method} {e.path}</code></td></tr>)}</tbody></table></div>}
    {d && <div className="row between"><span className="muted">{d.total} events</span><span><button disabled={page === 0} onClick={() => setPage(page - 1)}>← Prev</button> <button disabled={(page + 1) * 15 >= d.total} onClick={() => setPage(page + 1)}>Next →</button></span></div>}
    {sel && <EventModal e={sel} onClose={() => setSel(null)} />}</div>);
}

function Traffic({ id }) {
  const [range, setRange] = useState("1h"), [live, setLive] = useState(true);
  const [t] = useLive(() => api("GET", `/sites/${id}/analytics/traffic?range=${range}`), [id, range], live);
  const [s] = useLive(() => api("GET", `/sites/${id}/analytics/security?range=${range}`), [id, range], live);
  if (!t || !s) return <p>Loading…</p>;
  return (<div><RangeBar {...{ range, setRange, live, setLive }} />
    <div className="grid6"><Stat label="Requests" value={n(t.totals.total)} /><Stat label="Allowed" value={n(t.totals.allowed)} tone="green" /><Stat label="Blocked" value={n(t.totals.blocked)} tone="red" />
      <Stat label="Rate limited" value={n(t.totals.rate_limited)} tone="purple" /><Stat label="Detected, not blocked" value={n(s.by_type.detected)} tone="amber" /><Stat label="Avg / max latency" value={t.totals.avg_latency_ms == null ? "—" : `${t.totals.avg_latency_ms} / ${t.totals.max_latency_ms} ms`} /></div>
    <div className="card"><h2>Requests over time</h2><Bars series={t.series} /></div>
    <div className="cols"><div className="card"><h2>Detections by category</h2><HBars items={s.by_category} /><p className="muted">{s.note}</p></div>
      <div className="card"><h2>Top rules</h2>{s.top_rules.length === 0 ? <p className="muted">No rule matches.</p> : s.top_rules.map((r) => <div key={r.rule_id + r.message} className="hrow"><span className="hl"><code>{r.rule_id}</code></span><span style={{ flex: 1 }}>{r.message}</span><b>{r.count}</b></div>)}</div></div></div>);
}

export default function SiteDetail({ id, user, back, initialTab = "protection" }) {
  const [tab, setTab] = useState(initialTab), [s, setS] = useState(null), [vers, setVers] = useState([]), [audit, setAudit] = useState([]), [health, setHealth] = useState(null);
  const [err, setErr] = useState(null), [busy, setBusy] = useState(false), [confirm, setConfirm] = useState(false);
  const canWrite = user.role !== "analyst";
  const load = useCallback(async () => {
    try { const [a, b, c] = await Promise.all([api("GET", `/sites/${id}`), api("GET", `/sites/${id}/policy/versions`), api("GET", `/sites/${id}/audit?limit=25`)]); setS(a); setVers(b); setAudit(c.items); }
    catch (x) { setErr(x); } }, [id]);
  useEffect(() => { load(); }, [load]);
  const act = async (fn) => { setBusy(true); setErr(null); try { await fn(); } catch (x) { setErr(x); } finally { setBusy(false); setConfirm(false); load(); } };
  const setMode = (mode) => act(() => api("PUT", `/sites/${id}/protection`, { mode, expected_version: s.protection.effective_version }));
  const rollback = (v) => act(() => api("POST", `/sites/${id}/policy/rollback`, { to_version: v, expected_version: s.protection.effective_version }));
  const check = () => { setHealth("checking…"); api("GET", `/sites/${id}/health`).then(setHealth).catch((x) => setHealth({ status: "unavailable", detail: x.message })); };
  const remove = () => window.confirm(`Remove ${s.name}? Its routing is removed; audit history is kept.`) && act(async () => { await api("DELETE", `/sites/${id}`); back(); });
  if (!s) return <main><button className="link backlink" onClick={back}><IconBack />All websites</button><Errors err={err} />Loading…</main>;
  const p = s.protection, cur = MODE[p.effective_mode] || { label: p.effective_mode, cls: "bad", help: "" }, sy = SYNC[p.sync_state] || [p.sync_state, "warn"];
  const card = (mode, title, sub) => <button disabled={!canWrite || busy || p.effective_mode === mode} data-mode={mode} aria-pressed={p.effective_mode === mode} className={`modecard ${p.effective_mode === mode ? "on" : ""}`}
    onClick={() => (mode === "disabled" ? setConfirm(true) : setMode(mode))}><b>{title}</b><small>{sub}</small></button>;
  return (<main><button className="link backlink" onClick={back}><IconBack />All websites</button>
    <div className="sitehead"><div><h1>{s.name}</h1><div className="muted">{s.hostname}</div></div><div className="badges"><Badge cls={cur.cls}>{cur.label}</Badge><Badge cls={sy[1]}>{sy[0]}</Badge></div></div>
    <div className="tabs">{[["protection", "Protection"], ["policy", "Policy"], ["traffic", "Traffic & security"], ["events", "Events"], ["checks", "Security checks"], ["alerts", "Alerts"], ["history", "History"]].map(([k, l]) => <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{l}</button>)}</div>
    <Errors err={err} />{s.warnings.map((w, i) => <div key={i} className={`alert ${p.effective_mode === "disabled" || p.sync_state !== "in_sync" || p.requested_status === "failed" ? "bad" : "warn"}`}>⚠ {w}</div>)}
    {tab === "protection" && <>
      <div className="card"><h2>Protection mode</h2><p className="muted">{cur.help} Policy v{p.effective_version}{p.requested_version !== p.effective_version ? ` (requested v${p.requested_version}: ${p.requested_status})` : ""}.</p>
        <div className="modes">{card("blocking", "Enable blocking", "Enforce rules; block attacks")}{card("monitoring", "Monitoring only", "Detect and log, do not block")}{card("disabled", "Disable protection", "Turn the firewall off for this site")}</div>
        {!canWrite && <p className="muted">Read-only role: you cannot change protection.</p>}
        <p className="muted">A change is applied, then verified against the running proxy before it is shown as done. If it fails, the previous policy stays in effect.</p></div>
      <div className="card"><h2>Health</h2><button onClick={check}>Run live check</button>{health && <p>{typeof health === "string" ? health : <><Badge cls={health.status === "healthy" ? "ok" : "bad"}>{health.status}</Badge> <span className="muted">{health.detail}</span></>}</p>}</div>
      {s.origin_host && <div className="card"><h2>Configuration</h2><dl className="facts"><dt>Origin</dt><dd><code>{s.origin_scheme}://{s.origin_host}:{s.origin_port}</code></dd><dt>Environment</dt><dd>{s.environment || "Not set"}</dd><dt>Hostnames</dt><dd>{s.allowed_hostnames.join(", ")}</dd></dl></div>}
      {user.role === "admin" && <button className="danger" onClick={remove} disabled={busy}>Remove website</button>}</>}
    {tab === "policy" && <PolicyTab id={id} user={user} onSaved={load} />}
    {tab === "checks" && <Checks id={id} user={user} />}
    {tab === "alerts" && <Alerts id={id} user={user} />}
    {tab === "traffic" && <Traffic id={id} />}
    {tab === "events" && <Events id={id} />}
    {tab === "history" && <>
      <div className="card"><h2>Policy versions</h2><table><thead><tr><th>Ver</th><th>Mode</th><th>Status</th><th>By</th><th>When</th><th /></tr></thead><tbody>
        {vers.map((v) => <tr key={v.version}><td>{v.version}</td><td>{v.config.mode}</td><td>{v.status}{v.rollback_of ? ` (rollback of v${v.rollback_of})` : ""}{v.error ? ` — ${v.error}` : ""}</td><td>{v.created_by}</td><td>{when(v.created_at)}</td>
          <td>{canWrite && v.status === "applied" && v.version !== p.effective_version && <button disabled={busy} onClick={() => rollback(v.version)}>Restore</button>}</td></tr>)}</tbody></table></div>
      <div className="card"><h2>Administrative activity</h2><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Result</th></tr></thead><tbody>{audit.map((a) => <tr key={a.id}><td>{when(a.ts)}</td><td>{a.actor}</td><td>{a.action}</td><td>{a.result}</td></tr>)}</tbody></table></div></>}
    {confirm && <Confirm site={s} busy={busy} onNo={() => setConfirm(false)} onYes={() => setMode("disabled")} />}</main>);
}
