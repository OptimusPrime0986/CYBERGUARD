import React, { useState } from "react";
import { api } from "./api.js";
import { useLive } from "./hooks.js";
import { Bars, HBars, Stat, Badge, SEV, n } from "./charts.jsx";

export const MODE = {
  blocking: { label: "Blocking", cls: "ok", help: "Attacks are detected and blocked before they reach the website." },
  monitoring: { label: "Monitoring only", cls: "warn", help: "Attacks are detected and logged but NOT blocked." },
  disabled: { label: "Protection disabled", cls: "bad", help: "The firewall is not inspecting this site. Traffic still flows through the proxy." },
};
export const SYNC = { in_sync: ["Verified", "ok"], out_of_sync: ["Out of sync", "bad"], unverified: ["Unverified", "warn"], unknown: ["Unknown", "bad"], pending: ["Pending", "warn"] };
export const RANGES = ["15m", "1h", "24h", "7d"];
export const Errors = ({ err }) => !err ? null : (
  <div className="alert bad" role="alert"><b>{err.message}</b>
    {err.data?.details && <ul>{err.data.details.map((d, i) => <li key={i}>{d}</li>)}</ul>}
    {err.data?.detail && <div className="muted">{err.data.stage}: {err.data.detail}</div>}</div>);
export const when = (t) => (t ? new Date(t).toLocaleString() : "—");

export function RangeBar({ range, setRange, live, setLive }) {
  return (<div className="row end">
    <div className="seg">{RANGES.map((r) => <button key={r} className={r === range ? "on" : ""} onClick={() => setRange(r)}>{r}</button>)}</div>
    <label className="live"><input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live (5s)</label></div>);
}

export default function Overview({ user, open, addSite }) {
  const [range, setRange] = useState("1h"), [live, setLive] = useState(true);
  const [data, err] = useLive(() => api("GET", `/analytics/overview?range=${range}`), [range], live);
  const [sites] = useLive(() => api("GET", "/sites"), [], live);
  if (!data || !sites) return <main><Errors err={err} />Loading…</main>;
  const { traffic: tr, security: sec, per_site: ps, pipeline: pl } = data, t = tr.totals;
  const by = Object.fromEntries(ps.map((p) => [p.site_id, p]));
  const attention = sites.filter((s) => s.protection.sync_state !== "in_sync").length;
  return (<main>
    <div className="row between"><h1>Overview</h1><RangeBar {...{ range, setRange, live, setLive }} /></div>
    {pl.status !== "ok" && <div className={`alert ${pl.status === "waiting" ? "warn" : "bad"}`}>Event pipeline: <b>{pl.status}</b>. {pl.detail} Charts below stay empty until proxy logs arrive.</div>}
    <div className="grid6">
      <Stat label="Requests" value={n(t.total)} sub={t.avg_latency_ms != null ? `avg ${t.avg_latency_ms} ms` : null} />
      <Stat label="Allowed" value={n(t.allowed)} tone="green" />
      <Stat label="Blocked" value={n(t.blocked)} tone="red" sub="stopped before the website" />
      <Stat label="Detected, not blocked" value={n(sec.by_type.detected)} tone="amber" sub="monitoring / disabled / below threshold" />
      <Stat label="Rate limited" value={n(t.rate_limited)} tone="purple" sub="HTTP 429" />
      <Stat label="Rejected" value={n(t.rejected)} sub="method / size / format" />
      <Stat label="Sites needing attention" value={attention} tone={attention ? "red" : ""} />
    </div>
    <div className="card"><h2>Requests over time</h2><Bars series={tr.series} /></div>
    <div className="cols">
      <div className="card"><h2>Detections by category</h2><HBars items={sec.by_category} /><p className="muted">{sec.note}</p></div>
      <div className="card"><h2>Events by severity</h2><HBars items={Object.entries(sec.by_severity).map(([label, value]) => ({ label, value }))} colorFor={(l) => ({ critical: "b-bad", high: "b-bad", medium: "b-warn", low: "b-ok" }[l] || "b-mute")} /></div>
    </div>
    <div className="cols">
      <div className="card"><h2>Top triggered rules</h2>{sec.top_rules.length === 0 ? <p className="muted">No rule matches in this period.</p> :
        <table><thead><tr><th>Rule</th><th>Description</th><th>Hits</th></tr></thead><tbody>{sec.top_rules.map((r) => <tr key={r.rule_id + r.message}><td><code>{r.rule_id}</code></td><td>{r.message}</td><td>{r.count}</td></tr>)}</tbody></table>}</div>
      <div className="card"><h2>Recent critical / high events</h2>{sec.recent.length === 0 ? <p className="muted">None in this period.</p> :
        sec.recent.map((e) => <div key={e.id} className="ev" onClick={() => open(e.site_id, "events")}><Badge cls={e.event_type === "blocked" ? "bad" : "warn"}>{e.event_type}</Badge> <b>{e.site_id}</b> <code>{e.path}</code><div className="muted">{e.message} · {when(e.ts)}</div></div>)}</div>
    </div>
    <div className="row between" style={{ marginBottom: 12 }}><h2 style={{ margin: 0 }}>Websites</h2>{user.role === "admin" && sites.length > 0 && <button className="primary" onClick={addSite}>Add website</button>}</div>
    {sites.length === 0 ? <div className="card empty"><b>No websites yet</b><p>Add a website to start routing its traffic through the firewall.</p>{user.role === "admin" ? <button className="primary" onClick={addSite}>Add website</button> : <p>Ask an administrator to add one and give you access.</p>}</div> :
    <div className="sites"><div className="sites-head"><span>Website</span><span>Protection</span><span className="num">Requests</span><span className="num">Blocked</span><span className="num">Detected</span></div>
      {sites.map((s) => { const p = s.protection, md = MODE[p.effective_mode] || { label: p.effective_mode, cls: "bad" }, sy = SYNC[p.sync_state] || [p.sync_state, "warn"], m = by[s.site_id] || {};
        return (<div key={s.site_id} className="sitecard siterow" data-mode={p.effective_mode} role="button" tabIndex={0} onClick={() => open(s.site_id)} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && open(s.site_id)}>
          <div className="sname"><b>{s.name}</b><div className="muted">{s.hostname}</div>{s.warnings[0] && <div className="rowwarn">{s.warnings[0]}</div>}</div>
          <div className="badges"><Badge cls={md.cls}>{md.label}</Badge><Badge cls={sy[1]}>{sy[0]}</Badge></div>
          <span className="num">{n(m.total)}</span><span className="num">{n(m.blocked)}</span><span className="num">{n(m.detected)}</span></div>); })}</div>}
    <div className="card"><h2>Demo sites for testing attacks</h2><p className="muted">Add them with “Add website” (the form has quick-fill buttons), then open them through the firewall. Each has an attack guide page.</p>
      <p><a href="http://bank.localhost:8000" target="_blank" rel="noreferrer">ZenithBank at bank.localhost:8000</a><br /><a href="http://shop.localhost:8000" target="_blank" rel="noreferrer">ShopEasy at shop.localhost:8000</a></p></div>
  </main>);
}
