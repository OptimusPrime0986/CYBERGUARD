"""TOTP two-factor login (RFC 6238, SHA-1, 6 digits, 30s) using only the standard library; secrets encrypted at rest (A07)."""
import base64, hashlib, hmac, secrets, struct, time
from urllib.parse import quote
from cryptography.fernet import Fernet, InvalidToken


def new_secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def verify(secret, code, last_step=0, now=None, window=1):
    """-> the accepted time step, or None. A step can be used once (replay protection)."""
    code, now = str(code or "").strip().replace(" ", ""), (time.time() if now is None else now)
    if not (code.isdigit() and len(code) == 6): return None
    cur = int(now // 30)
    for st in range(cur - window, cur + window + 1):
        if st > last_step and hmac.compare_digest(code_at(secret, st), code): return st
    return None


def uri(email, secret): return f"otpauth://totp/CyberGuard:{quote(email)}?secret={secret}&issuer=CyberGuard"


def _f(app_secret): return Fernet(base64.urlsafe_b64encode(hashlib.sha256(("cg-totp|" + app_secret).encode()).digest()))
def seal(app_secret, totp_secret): return _f(app_secret).encrypt(totp_secret.encode()).decode()
def unseal(app_secret, blob):
    try: return _f(app_secret).decrypt(blob.encode()).decode()
    except (InvalidToken, AttributeError): return None
