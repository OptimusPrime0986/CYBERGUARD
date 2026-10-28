import React, { useState } from "react";
import { api } from "./api.js";
import { Errors } from "./Overview.jsx";

export default function Account({ user, refresh }) {
  const [setup, setSetup] = useState(null), [code, setCode] = useState(""), [err, setErr] = useState(null), [msg, setMsg] = useState(null);
  const go = async (fn, ok) => { setErr(null); setMsg(null); try { await fn(); setMsg(ok); setCode(""); setSetup(null); refresh(); } catch (x) { setErr(x); } };
  return (<main style={{ maxWidth: 620 }}><h1>My account</h1><div className="card"><h2>Two-factor sign-in</h2>
    <p className="muted">Adds a 6-digit code from an authenticator app (Google Authenticator, Authy, 1Password…) to your password. Strongly recommended for administrators.</p>
    <Errors err={err} />{msg && <div className="alert ok">{msg}</div>}
    {user.totp_enabled ? <><div className="alert ok">Two-factor sign-in is ON for {user.email}.</div>
      <label>To turn it off, enter a current code<input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" maxLength={6} /></label><button onClick={() => go(() => api("POST", "/auth/2fa/disable", { code }), "Two-factor sign-in turned off.")}>Turn off</button></>
      : !setup ? <button className="primary" onClick={async () => { setErr(null); try { setSetup(await api("POST", "/auth/2fa/setup")); } catch (x) { setErr(x); } }}>Set up two-factor sign-in</button>
      : <><p>1. In your authenticator app choose “enter a setup key” and type this key (account: CyberGuard, time-based):</p><div className="secret">{setup.secret}</div>
        <p className="small">Or paste this link into an app that accepts otpauth links: <code>{setup.uri}</code></p><p>2. Enter the 6-digit code it shows:</p>
        <input value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" maxLength={6} placeholder="123456" /><button className="primary" onClick={() => go(() => api("POST", "/auth/2fa/enable", { code }), "Two-factor sign-in is now ON. You will be asked for a code at your next sign-in.")}>Confirm and turn on</button></>}
    <p className="small">If you lose your device an administrator can reset it. There are no recovery codes in this version.</p></div></main>);
}
