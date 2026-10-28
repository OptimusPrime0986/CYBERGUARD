import React from "react";
export const n = (x) => (x == null ? "—" : x >= 10000 ? (x / 1000).toFixed(1) + "k" : String(x));
export const Badge = ({ cls = "neutral", children }) => <span className={`badge ${cls}`}>{children}</span>;
export const SEV = { critical: "bad", high: "bad", medium: "warn", low: "ok", informational: "neutral" };

export function Stat({ label, value, tone, sub }) {
  return <div className={`metric ${tone || ""}`}><span>{label}</span><b>{value}</b>{sub && <small>{sub}</small>}</div>;
}

// Stacked bars: allowed / rejected / blocked per time bucket. Pure SVG, no dependencies.
export function Bars({ series, height = 150 }) {
  const W = 600, pad = 22, bw = W / Math.max(series.length, 1);
  const tot = (s) => s.allowed + s.rejected + (s.limited || 0) + s.blocked;
  const max = Math.max(1, ...series.map(tot));
  const h = (v) => (v / max) * (height - pad);
  const label = (t) => (t ? t.slice(5, 16).replace("T", " ") : "");
  const empty = series.every((s) => tot(s) === 0);
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${height}`} width="100%" role="img" aria-label="Requests over time">
        {series.map((s, i) => {
          let y = height - pad;
          const seg = (v, cls) => { const hh = h(v); y -= hh; return hh > 0 ? <rect key={cls} x={i * bw + 1} y={y} width={Math.max(bw - 2, 1)} height={hh} rx="1.5" className={cls} /> : null; };
          return (<g key={s.t}><title>{`${label(s.t)}: ${s.allowed} allowed, ${s.blocked} blocked, ${s.limited || 0} rate-limited, ${s.rejected} rejected`}</title>
            {seg(s.allowed, "b-flow")}{seg(s.rejected, "b-warn")}{seg(s.limited || 0, "b-pur")}{seg(s.blocked, "b-bad")}</g>);
        })}
        <line x1="0" x2={W} y1={height - pad} y2={height - pad} className="axis" />
        <text x="0" y={height - 6} className="axtxt">{label(series[0]?.t)}</text>
        <text x={W} y={height - 6} textAnchor="end" className="axtxt">{label(series[series.length - 1]?.t)}</text>
        <text x={W} y="10" textAnchor="end" className="axtxt">peak {max}</text>
      </svg>
      {empty && <p className="muted center">No requests in this period.</p>}
      <div className="legend"><span><i className="dot b-flow" />Allowed</span><span><i className="dot b-warn" />Rejected (validation)</span><span><i className="dot b-pur" />Rate limited</span><span><i className="dot b-bad" />Blocked by firewall</span></div>
    </div>);
}

export function HBars({ items, colorFor, empty = "Nothing recorded in this period." }) {
  if (!items.length || items.every((i) => !i.value)) return <p className="muted">{empty}</p>;
  const max = Math.max(1, ...items.map((i) => i.value));
  return <div>{items.map((i) => (
    <div className="hrow" key={i.label}><span className="hl">{i.label}</span>
      <div className="hbar"><div style={{ width: `${(i.value / max) * 100}%` }} className={colorFor ? colorFor(i.label) : "b-acc"} /></div><b>{i.value}</b></div>))}</div>;
}
