"""Protected test origin ("CyberGuard Demo Site").

DELIBERATELY INERT: it never runs SQL, shell commands or file reads. It only (a) logs every request that
actually reaches it, so tests can prove a WAF-blocked request never arrived, and (b) serves a demo page
with an attack lab. Anything echoed back is JSON or inserted with textContent, so nothing is executable.
"""
import json, os, threading, time
from flask import Flask, request, jsonify, Response

app = Flask(__name__)
LOG = os.environ.get("CG_ORIGIN_LOG", "/data/requests.jsonl")
_lock = threading.Lock()
M = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberGuard Demo Site</title>
<style>
body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:0 auto;padding:20px;background:#f6f7f9;color:#1b1f24}
@media(prefers-color-scheme:dark){body{background:#12151a;color:#e8ebef}td,th{border-color:#2c333d!important}input,select{background:#1b2027;color:#e8ebef;border-color:#2c333d!important}}
h1{font-size:22px}.card{border:1px solid #8884;border-radius:10px;padding:14px;margin:14px 0}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:6px;border-bottom:1px solid #dfe3e8;vertical-align:top;word-break:break-all}
button{font:inherit;padding:6px 12px;border-radius:8px;border:1px solid #8886;cursor:pointer}button.go{background:#2457d6;color:#fff;border-color:#2457d6}
input,select{font:inherit;padding:6px;border:1px solid #dfe3e8;border-radius:8px}
.b{padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.blocked{background:#e3f4ea;color:#14733b}.allowed{background:#fff3d6;color:#8a5a00}.bad{background:#fde6e4;color:#a3201a}.ok{background:#e3f4ea;color:#14733b}
code{font-size:12px}
</style></head><body>
<h1>CyberGuard Demo Site</h1>
<p>This page was delivered <b>through your firewall</b>. The site behind it is deliberately inert: it never runs SQL, commands or file reads. It only tells you whether a request <i>reached</i> it.</p>
<div class="card"><b>Attack lab.</b> Each row sends a harmless, well-known attack string to this site.
<ul><li><b>Blocking mode:</b> attacks should show <span class="b blocked">BLOCKED by WAF</span>; normal requests should show <span class="b ok">ALLOWED</span>.</li>
<li><b>Monitoring only / Disabled:</b> attacks will show <span class="b allowed">NOT BLOCKED</span> (in monitoring they are detected but not stopped).</li></ul>
<button class="go" id="all">Run all tests</button> <span id="sum"></span>
<table><thead><tr><th>Test</th><th>Sent</th><th>Result</th><th></th></tr></thead><tbody id="rows"></tbody></table></div>
<div class="card"><b>Try your own input</b><p>
<select id="ep"><option value="/search?q=">search (q)</option><option value="/comment?text=">comment (text)</option><option value="/download?file=">download (file)</option><option value="/ping?host=">ping (host)</option></select>
<input id="val" size="40" placeholder="type anything"> <button id="send">Send</button> <span id="mine"></span></p></div>
<script>
const T=[
 {n:"SQL injection: tautology",a:1,p:"/search?q=",v:"' OR '1'='1"},
 {n:"SQL injection: UNION SELECT",a:1,p:"/search?q=",v:"1 UNION SELECT username,password FROM users--"},
 {n:"XSS: script tag",a:1,p:"/comment?text=",v:"\u003cscript\u003ealert(1)\u003c/script\u003e"},
 {n:"XSS: img onerror",a:1,p:"/comment?text=",v:"\u003cimg src=x onerror=alert(1)\u003e"},
 {n:"Path traversal",a:1,p:"/download?file=",v:"../../../../etc/passwd"},
 {n:"Command injection",a:1,p:"/ping?host=",v:"127.0.0.1; cat /etc/passwd"},
 {n:"Normal: search with SQL-ish words",a:0,p:"/search?q=",v:"how to select a good union rep"},
 {n:"Normal: plain text",a:0,p:"/comment?text=",v:"Great product, five stars"},
 {n:"Normal: unicode",a:0,p:"/search?q=",v:"caf\u00e9 \u6771\u4eac"}
];
async function send(path,v){
  try{const r=await fetch(path+encodeURIComponent(v));let b="";try{b=await r.text()}catch(e){}
    return {s:r.status,reached:r.status===200&&b.indexOf('"reached_origin"')>=0};}
  catch(e){return {s:0,reached:false}}}
function badge(res,attack){
  const sp=document.createElement("span");sp.className="b";
  if(res.s===403){sp.textContent="BLOCKED by WAF (403)";sp.className+=attack?" blocked":" bad";}
  else if(res.reached){sp.textContent=attack?"NOT BLOCKED (reached site)":"ALLOWED";sp.className+=attack?" allowed":" ok";}
  else{sp.textContent="Other: HTTP "+res.s;sp.className+=" bad";}
  return sp;}
const rows=document.getElementById("rows"),cells=[];
T.forEach((t,i)=>{const tr=document.createElement("tr");
  const c1=document.createElement("td");c1.textContent=t.n;
  const c2=document.createElement("td");const code=document.createElement("code");code.textContent=t.v;c2.appendChild(code);
  const c3=document.createElement("td");c3.textContent="—";
  const c4=document.createElement("td");const b=document.createElement("button");b.textContent="Send";b.onclick=()=>one(i);c4.appendChild(b);
  tr.append(c1,c2,c3,c4);rows.appendChild(tr);cells.push(c3);});
async function one(i){const t=T[i],r=await send(t.p,t.v);cells[i].replaceChildren(badge(r,t.a));return {t,r};}
document.getElementById("all").onclick=async()=>{let blocked=0,att=0,fp=0;
  for(let i=0;i<T.length;i++){const {t,r}=await one(i);if(t.a){att++;if(r.s===403)blocked++;}else if(r.s===403)fp++;}
  document.getElementById("sum").textContent=blocked+" of "+att+" attacks blocked; "+fp+" normal requests wrongly blocked.";};
document.getElementById("send").onclick=async()=>{const r=await send(document.getElementById("ep").value,document.getElementById("val").value);
  document.getElementById("mine").replaceChildren(badge(r,1));};
</script></body></html>"""


@app.route("/", defaults={"path": ""}, methods=M)
@app.route("/<path:path>", methods=M)
def catch_all(path):
    entry = {"ts": time.time(), "method": request.method, "path": request.path,
             "query": request.query_string.decode("utf-8", "replace"),
             "test_id": request.headers.get("X-Test-Id"), "body_len": len(request.get_data())}
    with _lock, open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    if request.method == "GET" and request.path == "/" and "text/html" in request.headers.get("Accept", ""):
        return Response(PAGE, mimetype="text/html")
    return jsonify(status="ok", reached_origin=True, test_id=entry["test_id"],
                   received={"path": request.path, "query": entry["query"][:200]})
