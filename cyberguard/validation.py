"""Input validation. Everything rendered into engine config MUST pass through here."""
import ipaddress, re, socket
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Callable

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOST_RE = re.compile(rf"^(?=.{{1,253}}$){LABEL}(?:\.{LABEL})*$")
SITE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
MODES = ("blocking", "monitoring", "disabled")
ENVIRONMENTS = ("production", "staging", "development")
MAX_BODY = 1 << 30


class ValidationError(ValueError):
    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _resolve(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        raise ValidationError([f"origin_host {host!r} cannot be resolved"])


@dataclass(frozen=True)
class AdminPolicy:
    """Platform-admin controlled. Owners cannot change this (anti-SSRF / open-proxy control)."""
    allowed_origin_hosts: frozenset = frozenset()   # exact names explicitly allowed (e.g. docker service names)
    allowed_origin_cidrs: tuple = ()                # networks allowed even though non-public
    allow_insecure_origin_tls: bool = False
    allow_site_wide_exclusions: bool = False        # exclusions must name a path or a parameter unless an admin allows more
    trusted_proxies: tuple = ()                     # CIDRs whose X-Forwarded-For is believed (e.g. your TLS load balancer)
    public_https_port: int = 443                    # port used in http->https redirects
    resolver: Callable = field(default=_resolve, compare=False)


def _is_restricted(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (not ip.is_global) or ip.is_multicast   # loopback, link-local, private, metadata, CGNAT, reserved...


@dataclass(frozen=True)
class Site:
    site_id: str
    name: str
    hostname: str
    origin_host: str
    origin_port: int
    origin_scheme: str
    tls_verify: bool
    allowed_hostnames: tuple
    environment: str = None

    def to_dict(self):
        d = asdict(self); d["allowed_hostnames"] = list(self.allowed_hostnames); return d

    @classmethod
    def from_dict(cls, d):
        d = dict(d); d["allowed_hostnames"] = tuple(d["allowed_hostnames"]); return cls(**d)


RULE_ID_RE = re.compile(r"^\d{6,7}$")
PROTECTED_RULES = {"949110", "959100", "980130", "980140", "980170"}     # blocking evaluation/correlation: never excludable
TARGET_RE = re.compile(r"^(ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_HEADERS):[A-Za-z0-9_.\-]{1,64}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9/_.\-]{0,100}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,23}$")
HTTPS_MODES = ("off", "optional", "redirect")
_EX_KEYS = ("rule_id", "path", "target", "reason", "expires", "created_by", "created_at")


@dataclass(frozen=True)
class Policy:
    mode: str = "blocking"
    max_body_bytes: int = 10 * 1024 * 1024
    allowed_methods: tuple = METHODS
    paranoia_level: int = 1          # 1 (fewest false positives) .. 4 (strictest)
    anomaly_threshold: int = 5       # lower = stricter; CRS critical match scores 5
    rate_limits: tuple = ()          # ({"name","path","per_minute","burst"}, ...)
    exclusions: tuple = ()           # narrow rule exclusions, see validate_policy
    security_headers: bool = True    # nosniff, frame, referrer, permissions headers (replace the origin's)
    generic_errors: bool = True      # replace origin 500/502/503/504 bodies with a generic page (hides stack traces)
    inspect_responses: bool = False  # CRS outbound leak rules (needs response-body buffering; off by default)
    https: str = "off"               # off | optional | redirect (needs an installed certificate)
    hsts: bool = False

    def to_dict(self):
        d = asdict(self)
        d["allowed_methods"] = list(self.allowed_methods)
        d["rate_limits"] = [dict(r) for r in self.rate_limits]
        d["exclusions"] = [dict(e) for e in self.exclusions]
        return d

    @classmethod
    def from_dict(cls, d):
        known = {f for f in cls.__dataclass_fields__}
        d = {k: v for k, v in dict(d).items() if k in known}      # old stored policies simply lack the newer fields
        if "allowed_methods" in d: d["allowed_methods"] = tuple(d["allowed_methods"])
        if "rate_limits" in d: d["rate_limits"] = tuple(d["rate_limits"])
        if "exclusions" in d: d["exclusions"] = tuple(d["exclusions"])
        return cls(**d)


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)

def validate_site(raw, admin):
    errs, raw = [], dict(raw or {})
    known = {"site_id", "name", "hostname", "origin_host", "origin_port", "origin_scheme",
             "tls_verify", "allowed_hostnames", "environment"}
    errs += [f"unknown field {k!r}" for k in raw if k not in known]

    sid = raw.get("site_id")
    if not isinstance(sid, str) or not SITE_ID_RE.match(sid):
        errs.append("site_id must match ^[a-z0-9][a-z0-9_-]{1,31}$")
    name = raw.get("name")
    if not isinstance(name, str) or not (1 <= len(name) <= 100) or any(ord(c) < 32 for c in name):
        errs.append("name must be 1-100 printable characters")
    hostname = raw.get("hostname")
    if not isinstance(hostname, str) or not HOST_RE.match(hostname):
        errs.append("hostname is not a valid lowercase DNS name")
    port = raw.get("origin_port")
    if not _int(port) or not (1 <= port <= 65535):
        errs.append("origin_port must be an integer 1-65535")
    scheme = raw.get("origin_scheme", "https")
    if scheme not in ("http", "https"):
        errs.append("origin_scheme must be http or https")
    tls_verify = raw.get("tls_verify", True)
    if not isinstance(tls_verify, bool):
        errs.append("tls_verify must be boolean")
    elif tls_verify is False and not admin.allow_insecure_origin_tls:
        errs.append("tls_verify=false is not permitted by administrative policy")
    env = raw.get("environment")
    if env is not None and env not in ENVIRONMENTS:
        errs.append(f"environment must be one of {ENVIRONMENTS}")
    allowed = raw.get("allowed_hostnames") or ([hostname] if isinstance(hostname, str) else [])
    if not isinstance(allowed, list) or len(allowed) > 20 or not all(isinstance(h, str) and HOST_RE.match(h) for h in allowed):
        errs.append("allowed_hostnames must be a list (max 20) of valid DNS names")
        allowed = []

    ohost = raw.get("origin_host")
    if not isinstance(ohost, str) or not HOST_RE.match(ohost):
        errs.append("origin_host must be a DNS name or IPv4 address")
    elif ohost not in admin.allowed_origin_hosts:
        try:
            ips = [ohost] if _is_ip(ohost) else admin.resolver(ohost)
            for ip in map(ipaddress.ip_address, ips):
                if any(ip in ipaddress.ip_network(c) for c in admin.allowed_origin_cidrs):
                    continue
                if _is_restricted(ip):
                    errs.append(f"origin_host resolves to restricted address {ip}")
                    break
        except ValidationError as e:
            errs += e.errors
    if errs:
        raise ValidationError(errs)
    hosts = tuple(dict.fromkeys([hostname, *allowed]))
    return Site(sid, name, hostname, ohost, port, scheme, tls_verify, hosts, env)


def _is_ip(s):
    try:
        ipaddress.ip_address(s); return True
    except ValueError:
        return False


def validate_policy(raw=None, admin=None):
    admin = admin or AdminPolicy()
    errs, raw = [], dict(raw or {})
    d = Policy()
    errs += [f"unknown field {k!r}" for k in raw if k not in Policy.__dataclass_fields__]
    mode = raw.get("mode", d.mode)
    if mode not in MODES: errs.append(f"mode must be one of {MODES}")
    body = raw.get("max_body_bytes", d.max_body_bytes)
    if not _int(body) or not (1 <= body <= MAX_BODY): errs.append(f"max_body_bytes must be an integer 1-{MAX_BODY}")
    m = raw.get("allowed_methods", list(d.allowed_methods))
    if not isinstance(m, (list, tuple)) or not m or any(x not in METHODS for x in m):
        errs.append(f"allowed_methods must be a non-empty subset of {METHODS}"); m = []
    pl = raw.get("paranoia_level", d.paranoia_level)
    if not _int(pl) or not 1 <= pl <= 4: errs.append("paranoia_level must be an integer 1-4")
    th = raw.get("anomaly_threshold", d.anomaly_threshold)
    if not _int(th) or not 1 <= th <= 100: errs.append("anomaly_threshold must be an integer 1-100")
    for k in ("security_headers", "generic_errors", "inspect_responses", "hsts"):
        if not isinstance(raw.get(k, getattr(d, k)), bool): errs.append(f"{k} must be true or false")
    https = raw.get("https", d.https)
    if https not in HTTPS_MODES: errs.append(f"https must be one of {HTTPS_MODES}")
    if raw.get("hsts") is True and https == "off": errs.append("hsts requires https to be 'optional' or 'redirect'")

    rl, seen = [], set()
    rules = raw.get("rate_limits", [])
    if not isinstance(rules, (list, tuple)) or len(rules) > 5: errs.append("rate_limits must be a list of at most 5 rules"); rules = []
    for r in rules:
        if not isinstance(r, dict) or set(r) - {"name", "path", "per_minute", "burst"}:
            errs.append("each rate limit needs only name, path, per_minute, burst"); continue
        n, pth, pm, bu = r.get("name"), r.get("path"), r.get("per_minute"), r.get("burst", 0)
        if not isinstance(n, str) or not NAME_RE.match(n) or n in seen: errs.append("rate limit name must be unique, lowercase letters/digits/-/_ (max 24)")
        elif not isinstance(pth, str) or not PATH_RE.match(pth): errs.append(f"rate limit {n!r}: path must start with / and use only letters, digits and / _ . -")
        elif not _int(pm) or not 1 <= pm <= 6000: errs.append(f"rate limit {n!r}: per_minute must be 1-6000")
        elif not _int(bu) or not 0 <= bu <= 1000: errs.append(f"rate limit {n!r}: burst must be 0-1000")
        else: seen.add(n); rl.append({"name": n, "path": pth, "per_minute": pm, "burst": bu})

    ex = []
    items = raw.get("exclusions", [])
    if not isinstance(items, (list, tuple)) or len(items) > 50: errs.append("exclusions must be a list of at most 50"); items = []
    for e in items:
        if not isinstance(e, dict) or set(e) - set(_EX_KEYS): errs.append(f"each exclusion may only contain {_EX_KEYS}"); continue
        rid, pth, tgt, why, exp = e.get("rule_id"), e.get("path"), e.get("target"), e.get("reason"), e.get("expires")
        if not isinstance(rid, str) or not RULE_ID_RE.match(rid): errs.append("exclusion rule_id must be a 6-7 digit rule id"); continue
        if rid in PROTECTED_RULES: errs.append(f"rule {rid} (blocking evaluation) cannot be excluded"); continue
        if pth is not None and (not isinstance(pth, str) or not PATH_RE.match(pth)): errs.append(f"exclusion {rid}: invalid path"); continue
        if tgt is not None and (not isinstance(tgt, str) or not TARGET_RE.match(tgt)): errs.append(f"exclusion {rid}: target must look like ARGS:name, REQUEST_COOKIES:name or REQUEST_HEADERS:name"); continue
        if pth is None and tgt is None and not admin.allow_site_wide_exclusions:
            errs.append(f"exclusion {rid}: must be limited to a path and/or a parameter (site-wide exclusions need administrator permission)"); continue
        if not isinstance(why, str) or not 5 <= len(why) <= 200 or any(ord(c) < 32 for c in why): errs.append(f"exclusion {rid}: a reason of 5-200 printable characters is required"); continue
        if exp is not None:
            try: datetime.strptime(exp, "%Y-%m-%d")
            except (TypeError, ValueError): errs.append(f"exclusion {rid}: expires must be YYYY-MM-DD"); continue
        ex.append({k: e.get(k) for k in _EX_KEYS})
    if errs: raise ValidationError(errs)
    return Policy(mode, body, tuple(x for x in METHODS if x in m), pl, th, tuple(rl), tuple(ex),
                  raw.get("security_headers", d.security_headers), raw.get("generic_errors", d.generic_errors),
                  raw.get("inspect_responses", d.inspect_responses), https, raw.get("hsts", d.hsts))
