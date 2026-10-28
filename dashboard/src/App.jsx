import React, { useEffect, useState } from "react";
import { api, setCsrf } from "./api.js";
import Overview, { Errors } from "./Overview.jsx";
import SiteDetail from "./SiteDetail.jsx";
import Coverage from "./Coverage.jsx";
import Account from "./Account.jsx";
import { Logo, IconGrid, IconChecks, IconUsers, IconUser, IconOut } from "./icons.jsx";

function Login({ onLogin }) {
  const [f, setF] = useState({ email: "", password: "", code: "" }), [err, setErr] = useState(null), [needCode, setNeed] = useState(false);
  const go = async (e) => { e.preventDefault(); setErr(null); try { const r = await api("POST", "/auth/login", f); setCsrf(r.csrf); onLogin(r.user); } catch (x) { if (x.data?.error === "totp_required") { setNeed(true); } else setErr(x); } };
  return (<div className="login"><div className="loginbrand"><div className="brand"><Logo /><span>CyberGuard</span></div><h1>See what your firewall is stopping.</h1>
    <p>Every blocked attack, rate limit and policy change is recorded and explained, and every protection change is checked against the running proxy before it is reported as done.</p></div>
    <div className="loginform"><form onSubmit={go}><h2>Sign in</h2><p className="muted">Use the account your administrator created for you.</p>
      <label>Email<input type="email" autoComplete="username" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required /></label>
      <label>Password<input type="password" autoComplete="current-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required /></label>
      {needCode && <label>6-digit code from your authenticator app<input autoFocus inputMode="numeric" maxLength={6} value={f.code} onChange={(e) => setF({ ...f, code: e.target.value })} /></label>}
      <Errors err={err} /><button className="primary" type="submit" style={{ width: "100%" }}>{needCode ? "Verify and sign in" : "Sign in"}</button></form></div></div>);
}

function AddSite({ close, done }) {
  const [f, setF] = useState({ site_id: "", name: "", hostname: "", origin_host: "", origin_port: "443", origin_scheme: "https", owner_email: "", mode: "blocking" });
  const [err, setErr] = useState(null), [busy, setBusy] = useState(false), set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const preset = (id, name, host) => setF({ ...f, site_id: id, name, hostname: host, origin_host: "origin", origin_port: "5000", origin_scheme: "http" });
  const go = async (e) => { e.preventDefault(); setErr(null); setBusy(true); const { mode, owner_email, ...site } = f;
    try { await api("POST", "/sites", { ...site, origin_port: parseInt(site.origin_port, 10), ...(owner_email ? { owner_email } : {}), policy: { mode } }); done(); } catch (x) { setErr(x); } finally { setBusy(false); } };
  return (<div className="modal"><div className="card wide"><h2>Add website</h2>
    <p className="muted">Quick fill with a demo site: <button type="button" className="link" onClick={() => preset("bank", "ZenithBank", "bank.localhost")}>ZenithBank demo</button> · <button type="button" className="link" onClick={() => preset("shop", "ShopEasy", "shop.localhost")}>ShopEasy demo</button></p>
    <form onSubmit={go}>
      <div className="row"><label>ID (a-z, 0-9, - _)<input value={f.site_id} onChange={set("site_id")} required /></label><label>Display name<input value={f.name} onChange={set("name")} required /></label></div>
      <label>Public hostname (what visitors type)<input value={f.hostname} onChange={set("hostname")} placeholder="www.example.com" required /></label>
      <div className="row"><label>Origin host (the real website)<input value={f.origin_host} onChange={set("origin_host")} required /></label><label>Port<input value={f.origin_port} onChange={set("origin_port")} required /></label>
        <label>Protocol<select value={f.origin_scheme} onChange={set("origin_scheme")}><option>https</option><option>http</option></select></label></div>
      <div className="row"><label>Initial mode<select value={f.mode} onChange={set("mode")}><option value="blocking">Blocking</option><option value="monitoring">Monitoring only</option></select></label>
        <label>Owner email (optional)<input type="email" value={f.owner_email} onChange={set("owner_email")} /></label></div>
      <p className="muted">Origins on private, loopback or metadata addresses are rejected unless the administrator allowed them.</p><Errors err={err} />
      <div className="row"><button type="button" onClick={close}>Cancel</button><button className="primary" disabled={busy}>{busy ? "Deploying and verifying…" : "Add and verify"}</button></div></form></div></div>);
}

function Users() {
  const [list, setList] = useState([]), [err, setErr] = useState(null), [ok, setOk] = useState(null), [sites, setSites] = useState([]), [f, setF] = useState({ email: "", password: "", role: "owner", site: "" });
  const load = () => api("GET", "/users").then(setList).catch(setErr);
  useEffect(() => { load(); api("GET", "/sites").then(setSites).catch(() => {}); }, []);
  const go = async (e) => { e.preventDefault(); setErr(null); setOk(null);
    try { await api("POST", "/users", { email: f.email, password: f.password, role: f.role, site_ids: f.site ? [f.site] : [] }); setOk("User created."); setF({ ...f, email: "", password: "" }); load(); } catch (x) { setErr(x); } };
  return (<main><h1>Users</h1><div className="card"><h2>Add user</h2><form onSubmit={go}><div className="row">
    <label>Email<input type="email" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} required /></label>
    <label>Password (12+ chars)<input type="password" autoComplete="new-password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} required /></label></div>
    <div className="row"><label>Role<select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}><option value="owner">Website owner</option><option value="analyst">Read-only analyst</option><option value="admin">Platform administrator</option></select></label>
      <label>Grant access to<select value={f.site} onChange={(e) => setF({ ...f, site: e.target.value })}><option value="">— none —</option>{sites.map((s) => <option key={s.site_id} value={s.site_id}>{s.name}</option>)}</select></label></div>
    <Errors err={err} />{ok && <div className="alert ok">{ok}</div>}<button className="primary">Create user</button></form></div>
    <div className="card"><table><thead><tr><th>Email</th><th>Role</th><th>Websites</th></tr></thead><tbody>{list.map((u) => <tr key={u.id}><td>{u.email}</td><td>{u.role}</td><td>{u.role === "admin" ? "all" : u.sites.join(", ") || "—"}</td></tr>)}</tbody></table></div></main>);
}

export default function App() {
  const [user, setUser] = useState(undefined), [view, setView] = useState({ page: "overview" }), [adding, setAdding] = useState(false), [tick, setTick] = useState(0);
  const refresh = () => api("GET", "/auth/me").then((r) => { setCsrf(r.csrf); setUser(r.user); }).catch(() => setUser(null));
  useEffect(() => { refresh(); }, []);
  if (user === undefined) return <main>Loading…</main>;
  if (!user) return <Login onLogin={setUser} />;
  const logout = async () => { try { await api("POST", "/auth/logout"); } finally { setCsrf(null); setUser(null); setView({ page: "overview" }); } };
  const ROLE = { admin: "Administrator", owner: "Website owner", analyst: "Analyst (read-only)" };
  const nav = [["overview", "Overview", <IconGrid />], ["coverage", "Coverage", <IconChecks />], ...(user.role === "admin" ? [["users", "Users", <IconUsers />]] : []), ["account", "Account", <IconUser />]];
  const active = view.page === "site" ? "overview" : view.page;
  return (<div className="shell"><aside className="side"><div className="brand"><Logo /><span>CyberGuard</span></div>
    <nav>{nav.map(([k, label, icon]) => <button key={k} className={k === active ? "navb on" : "navb"} aria-current={k === active ? "page" : undefined} onClick={() => setView({ page: k })}>{icon}<span>{label}</span></button>)}</nav>
    <div className="who"><div className="whoname">{user.email}</div><div className="whorole">{ROLE[user.role] || user.role}</div><button className="navb" onClick={logout}><IconOut /><span>Sign out</span></button></div></aside>
    <div className="page">
    {view.page === "overview" && <Overview key={tick} user={user} open={(id, tab) => setView({ page: "site", id, tab })} addSite={() => setAdding(true)} />}
    {view.page === "site" && <SiteDetail key={view.id + (view.tab || "")} id={view.id} initialTab={view.tab} user={user} back={() => setView({ page: "overview" })} />}
    {view.page === "users" && <Users />}
    {view.page === "coverage" && <Coverage user={user} />}
    {view.page === "account" && <Account user={user} refresh={refresh} />}
    {adding && <AddSite close={() => setAdding(false)} done={() => { setAdding(false); setTick(tick + 1); }} />}</div></div>);
}
