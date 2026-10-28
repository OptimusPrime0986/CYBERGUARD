import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import { Badge } from "./charts.jsx";
import { Errors, when } from "./Overview.jsx";

const METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const Check = ({ label, hint, v, on, dis }) => <label className="check"><input type="checkbox" checked={!!v} disabled={dis} onChange={(e) => on(e.target.checked)} /><span>{label}{hint && <span className="small"> — {hint}</span>}</span></label>;

export default function PolicyTab({ id, user, onSaved }) {
  const [rec, setRec] = useState(null), [p, setP] = useState(null), [tls, setTls] = useState(null), [err, setErr] = useState(null), [msg, setMsg] = useState(null), [busy, setBusy] = useState(false), [pem, setPem] = useState({ certificate: "", private_key: "" });
  const dis = user.role === "analyst";
  const load = () => Promise.all([api("GET", `/sites/${id}/policy`), api("GET", `/sites/${id}/tls`)]).then(([r, t]) => { setRec(r); setP(r.config); setTls(t); }).catch(setErr);
  useEffect(() => { load(); }, [id]);
  if (!p) return err ? <Errors err={err} /> : <p>Loading…</p>;
  const set = (k, v) => setP({ ...p, [k]: v });
  const row = (key, i, k, v) => set(key, p[key].map((x, j) => (j === i ? { ...x, [k]: v } : x)));
  const save = async () => { setBusy(true); setErr(null); setMsg(null);
    try { await api("PUT", `/sites/${id}/policy`, { ...p, expected_version: rec.version }); setMsg("Saved, deployed and verified."); await load(); onSaved && onSaved(); }
    catch (x) { setErr(x); } finally { setBusy(false); } };
  const cert = async (body) => { setBusy(true); setErr(null); setMsg(null); try { setTls(await api("POST", `/sites/${id}/tls`, body)); setMsg("Certificate installed."); setPem({ certificate: "", private_key: "" }); } catch (x) { setErr(x); } finally { setBusy(false); } };
  const n = (k) => (e) => set(k, e.target.value === "" ? "" : parseInt(e.target.value, 10));
  return (<div>
    <Errors err={err} />{msg && <div className="alert ok">{msg}</div>}
    <div className="card"><h2>Detection sensitivity</h2>
      <div className="row"><label>Paranoia level<select disabled={dis} value={p.paranoia_level} onChange={n("paranoia_level")}><option value={1}>1 — fewest false positives (default)</option><option value={2}>2 — stricter</option><option value={3}>3 — strict</option><option value={4}>4 — strictest, expect false positives</option></select></label>
        <label>Blocking threshold (1–100)<input type="number" disabled={dis} value={p.anomaly_threshold} onChange={n("anomaly_threshold")} /></label></div>
      <p className="small">A request is blocked when its anomaly score reaches the threshold. One critical rule match scores 5, so 5 blocks on any critical match; lower is stricter. Higher paranoia checks more patterns and flags more legitimate traffic: use Monitoring mode and the Events tab while tuning.</p></div>
    <div className="card"><h2>Rate limits <span className="small">(per client IP, enforced even if the firewall is disabled; Monitoring mode only logs)</span></h2>
      {p.rate_limits.map((r, i) => <div className="listrow" key={i}>
        <label>Name<input disabled={dis} value={r.name} onChange={(e) => row("rate_limits", i, "name", e.target.value)} /></label><label>Path starts with<input disabled={dis} value={r.path} onChange={(e) => row("rate_limits", i, "path", e.target.value)} /></label>
        <label>Requests / minute<input type="number" disabled={dis} value={r.per_minute} onChange={(e) => row("rate_limits", i, "per_minute", parseInt(e.target.value || 0, 10))} /></label><label>Burst<input type="number" disabled={dis} value={r.burst} onChange={(e) => row("rate_limits", i, "burst", parseInt(e.target.value || 0, 10))} /></label>
        {!dis && <button onClick={() => set("rate_limits", p.rate_limits.filter((_, j) => j !== i))}>Remove</button>}</div>)}
      {!dis && p.rate_limits.length < 5 && <button onClick={() => set("rate_limits", [...p.rate_limits, { name: "login", path: "/login", per_minute: 10, burst: 3 }])}>+ Add rate limit</button>}
      <p className="small">Excess requests get HTTP 429 with Retry-After. Limits are per IP address, so users behind one shared address share a limit, and attackers can spread across addresses. Nothing locks accounts out.</p></div>
    <div className="card"><h2>Rule exclusions <span className="small">(for false positives; keep them narrow)</span></h2>
      {p.exclusions.map((e, i) => <div key={i} className="listrow">
        <label>Rule id<input disabled={dis} value={e.rule_id || ""} onChange={(ev) => row("exclusions", i, "rule_id", ev.target.value)} /></label><label>Path starts with<input disabled={dis} value={e.path || ""} onChange={(ev) => row("exclusions", i, "path", ev.target.value || null)} /></label>
        <label>Parameter (e.g. ARGS:q)<input disabled={dis} value={e.target || ""} onChange={(ev) => row("exclusions", i, "target", ev.target.value || null)} /></label>
        <label>Reason<input disabled={dis} value={e.reason || ""} onChange={(ev) => row("exclusions", i, "reason", ev.target.value)} /></label>
        <label>Expires<input type="date" disabled={dis} value={e.expires || ""} onChange={(ev) => row("exclusions", i, "expires", ev.target.value || null)} /></label>
        <div className="small">{e.created_by ? `by ${e.created_by}, ${when(e.created_at)}` : "new"}{e.expires && e.expires < new Date().toISOString().slice(0, 10) ? " · EXPIRED" : ""}</div>
        {!dis && <button onClick={() => set("exclusions", p.exclusions.filter((_, j) => j !== i))}>Remove</button>}</div>)}
      {!dis && <button onClick={() => set("exclusions", [...p.exclusions, { rule_id: "", path: "/", target: null, reason: "", expires: null }])}>+ Add exclusion</button>}
      <p className="small">An exclusion must name a path and/or a parameter. Find the rule id in the Events tab. Expired exclusions stop applying and are removed automatically.</p></div>
    <div className="card"><h2>Hardening</h2>
      <Check dis={dis} label="Security headers" hint="nosniff, frame, referrer and permissions headers (replace the site's own copies)" v={p.security_headers} on={(v) => set("security_headers", v)} />
      <Check dis={dis} label="Generic error pages" hint="hide stack traces: origin 500/502/503/504 pages become a plain message" v={p.generic_errors} on={(v) => set("generic_errors", v)} />
      <Check dis={dis} label="Inspect responses for leaks" hint="CRS outbound rules; buffers response bodies, so it costs speed and memory" v={p.inspect_responses} on={(v) => set("inspect_responses", v)} /></div>
    <div className="card"><h2>Request limits</h2><div className="row"><label>Max body size (MB)<input type="number" disabled={dis} value={Math.round(p.max_body_bytes / 1048576 * 100) / 100} onChange={(e) => set("max_body_bytes", Math.max(1, Math.round(parseFloat(e.target.value || 1) * 1048576)))} /></label></div>
      <div className="small">Allowed methods</div><div className="row">{METHODS.map((m) => <Check key={m} dis={dis} label={m} v={p.allowed_methods.includes(m)} on={(v) => set("allowed_methods", METHODS.filter((x) => (x === m ? v : p.allowed_methods.includes(x))))} />)}</div></div>
    <div className="card"><h2>HTTPS</h2>
      <p>Certificate: {tls?.installed ? <><Badge cls={tls.self_signed || tls.days_left < 14 ? "warn" : "ok"}>{tls.self_signed ? "self-signed" : "installed"}</Badge> <span className="muted">expires in {tls.days_left} days · {tls.san.join(", ")}</span></> : <Badge cls="bad">none installed</Badge>}</p>
      <div className="row"><label>HTTPS mode<select disabled={dis || !tls?.installed} value={p.https} onChange={(e) => setP({ ...p, https: e.target.value, hsts: e.target.value === "off" ? false : p.hsts })}><option value="off">Off (plain HTTP only)</option><option value="optional">Optional (HTTP and HTTPS)</option><option value="redirect">Redirect HTTP to HTTPS</option></select></label></div>
      <Check dis={dis || p.https === "off"} label="HSTS" hint="tell browsers to insist on HTTPS for a year; turn on only when HTTPS works everywhere" v={p.hsts} on={(v) => set("hsts", v)} />
      {user.role === "admin" && <><button disabled={busy} onClick={() => cert({ mode: "self_signed" })}>Generate self-signed certificate (testing)</button>
        <details style={{ marginTop: 10 }}><summary>Install your own certificate (PEM)</summary><label>Certificate chain<textarea value={pem.certificate} onChange={(e) => setPem({ ...pem, certificate: e.target.value })} /></label>
          <label>Private key (never shown again)<textarea value={pem.private_key} onChange={(e) => setPem({ ...pem, private_key: e.target.value })} /></label><button disabled={busy || !pem.certificate || !pem.private_key} onClick={() => cert({ certificate: pem.certificate, private_key: pem.private_key })}>Install certificate</button></details></>}
      <p className="small">TLS 1.2 and 1.3 only. HTTPS listens on port 8443 in this demo setup. Certificate renewal is manual: install the new one before the old expires.</p></div>
    {!dis && <button className="primary" disabled={busy} onClick={save}>{busy ? "Applying and verifying…" : "Save policy"}</button>}
    {dis && <p className="muted">Read-only role: you cannot change the policy.</p>}</div>);
}
