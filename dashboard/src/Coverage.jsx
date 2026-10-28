import React, { useEffect, useState } from "react";
import { api } from "./api.js";
import { Badge } from "./charts.jsx";
import { Errors, when } from "./Overview.jsx";

const V = { verified: ["ok", "Verified by tests"], partial: ["warn", "Partly verified"], failed: ["bad", "Test failed"], not_verified: ["neutral", "Not verified"], not_tested: ["neutral", "Not tested yet"], no_waf_control: ["neutral", "No WAF control"] };
const T = { pass: "ok", fail: "bad", gap: "warn", skipped: "neutral", not_configured: "neutral" };

export default function Coverage({ user }) {
  const [d, setD] = useState(null), [err, setErr] = useState(null), [busy, setBusy] = useState(false);
  useEffect(() => { api("GET", "/coverage").then(setD).catch(setErr); }, []);
  const run = async () => { setBusy(true); setErr(null); try { setD(await api("POST", "/coverage/run")); } catch (x) { setErr(x); } finally { setBusy(false); } };
  if (!d) return <main><Errors err={err} />Loading…</main>;
  return (<main><div className="row between"><h1>OWASP Top 10:2025 coverage</h1>{user.role === "admin" && <button className="primary" disabled={busy} onClick={run}>{busy ? "Running tests…" : "Run coverage tests"}</button>}</div>
    <div className="alert warn">{d.note} No category is “protected” just because rules are installed. A WAF cannot fully address any of the ten.</div><Errors err={err} />
    <p className="muted">{d.last_run.ts ? `Last run ${when(d.last_run.ts)}; site modes at the time: ${Object.entries(d.last_run.modes || {}).map(([k, v]) => `${k}=${v}`).join(", ") || "n/a"}.` : "No test run yet."} The tests send attack requests to the demo sites (register them as bank.localhost and shop.localhost) and about 15 rapid requests for the rate-limit test. Run them in <b>Blocking</b> mode.</p>
    <div className="card" style={{ overflow: "auto" }}><table><thead><tr><th>Category</th><th>Status</th><th>What CyberGuard does</th><th>Needs the application</th></tr></thead><tbody>
      {d.categories.map((c) => <tr key={c.id} className="catrow"><td><b>{c.id}</b> {c.name}</td><td className="verdict"><Badge cls={V[c.verdict][0]}>{V[c.verdict][1]}</Badge></td>
        <td><div><b>Prevent:</b> {c.prevent}</div><div><b>Detect:</b> {c.detect}</div><div className="small">Limits: {c.limits}</div>
          {c.test_results.length > 0 && <ul className="tests">{c.test_results.map((t) => <li key={t.id}><Badge cls={T[t.status]}>{t.status}</Badge> {t.id}: {t.detail}</li>)}</ul>}</td><td>{c.app_level}</td></tr>)}</tbody></table></div></main>);
}
