"""Engine adapters. The controller never gets a Docker socket: FileAgentEngine talks to a
restricted agent in the proxy container through a shared volume (only `nginx -t` / reload)."""
import abc, os, time, uuid, json, urllib.request, urllib.error
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SiteExpectation:
    site_id: str
    hostname: str
    policy_version: int
    mode: str
    release: int
    https: str = "off"


@dataclass
class VerifyResult:
    ok: bool
    details: dict


class Engine(abc.ABC):
    @abc.abstractmethod
    def validate(self): """Validate the config currently linked as active. -> (ok, message). Must not reload."""
    @abc.abstractmethod
    def reload(self): """Graceful reload. -> (ok, message)"""
    @abc.abstractmethod
    def verify(self, expectations): """Check the RUNNING engine. -> VerifyResult"""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k): return None


def _http(url, headers=None, timeout=5, insecure=False, full=False):
    """-> (status, body) or, with full=True, (status, headers-dict-lowercase, body). Never follows redirects."""
    import ssl
    ctx = ssl._create_unverified_context() if insecure else None
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx)) if ctx else urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers or {})
    def pack(status, hdrs, body): return (status, {k.lower(): v for k, v in hdrs.items()}, body) if full else (status, body)
    try:
        with opener.open(req, timeout=timeout) as r:
            return pack(r.status, r.headers, r.read(200000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)


class FileAgentEngine(Engine):
    CANARY = "/__cg_canary?cg=%3Cscript%3Ealert(1)%3C%2Fscript%3E"   # inert payload

    def __init__(self, agent_dir, state_url, public_url, timeout=20, https_url=None):
        self.dir, self.state_url, self.public_url, self.timeout = Path(agent_dir), state_url, public_url, timeout
        self.https_url = https_url

    def _call(self, action):
        cid = uuid.uuid4().hex
        tmp = self.dir / f"{cid}.tmp"; tmp.write_text("")
        os.replace(tmp, self.dir / f"{cid}.{action}")
        res, end = self.dir / f"{cid}.result", time.time() + self.timeout
        while time.time() < end:
            if res.exists():
                first, _, rest = res.read_text().partition("\n"); res.unlink()
                return first.strip() == "OK", rest.strip()
            time.sleep(0.2)
        return False, f"agent did not answer '{action}' within {self.timeout}s"

    def validate(self): return self._call("validate")
    def reload(self): return self._call("reload")

    def verify(self, expectations):
        out, all_ok = {}, True
        for e in expectations:
            ok, detail = self._loaded(e)
            if ok:
                ok, detail = self._canary(e)
            out[e.site_id] = detail; all_ok &= ok
        return VerifyResult(all_ok, out)

    def _loaded(self, e):
        end, last = time.time() + self.timeout, "no response"
        while time.time() < end:
            st, body = _http(f"{self.state_url}/state/{e.site_id}")
            if st == 200:
                try:
                    d = json.loads(body)
                    if (d["policy_version"], d["mode"], d["release"]) == (e.policy_version, e.mode, e.release):
                        return True, "config loaded"
                    last = f"running config differs: {d}"
                except (ValueError, KeyError):
                    last = "unparseable state"
            else:
                last = f"state endpoint status {st}"
            time.sleep(0.4)
        return False, last

    def _canary(self, e):
        if e.https == "redirect" and self.https_url:      # HTTP only redirects, so probe the HTTPS listener (cert is not checked: we dial the proxy by name)
            st, _ = _http(self.https_url + self.CANARY, {"Host": e.hostname}, insecure=True)
        else:
            st, _ = _http(self.public_url + self.CANARY, {"Host": e.hostname})
        if e.mode == "blocking":
            return (st == 403, "config loaded; canary blocked (403)" if st == 403
                    else f"config loaded but canary NOT blocked (status {st}): enforcement unconfirmed")
        if st == 403:
            return False, "canary was blocked although mode is not blocking"
        return True, f"config loaded; canary not blocked (status {st})"
