import { useEffect, useState } from "react";
// Fetch on mount/deps change; optionally poll every 5s ("Live").
export function useLive(fn, deps, live) {
  const [data, setData] = useState(null), [err, setErr] = useState(null);
  useEffect(() => {
    let on = true;
    const go = () => fn().then((d) => { if (on) { setData(d); setErr(null); } }).catch((e) => on && setErr(e));
    go();
    const t = live ? setInterval(go, 5000) : null;
    return () => { on = false; if (t) clearInterval(t); };
    // eslint-disable-next-line
  }, [...deps, live]);
  return [data, err];
}
