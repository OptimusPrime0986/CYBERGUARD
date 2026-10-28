let csrf = null;
export const setCsrf = (t) => { csrf = t; };
export async function api(method, path, body) {
  const res = await fetch("/api/v1" + path, {
    method, credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(csrf ? { "X-CSRF-Token": csrf } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null; try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw Object.assign(new Error(data?.message || `Request failed (${res.status})`), { status: res.status, data });
  return data;
}
