"""Per-site TLS certificates (A04). Files live on the shared volume: <root>/tls/<site>/{fullchain.pem,privkey.pem}.
Private keys are never returned by any API. Supports a generated self-signed certificate (demo) or an uploaded PEM pair."""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .validation import ValidationError


def _dir(root, sid): return Path(root) / "tls" / sid


def self_signed(hostnames, days=90):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


def _matches(pattern, host):
    pattern = pattern.lower()
    return pattern == host or (pattern.startswith("*.") and host.split(".", 1)[-1] == pattern[2:] and "." in host)


def inspect(cert_pem, key_pem, hostnames):
    """Validate an uploaded pair; returns facts or raises ValidationError with a plain-language reason."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        raise ValidationError(["certificate is not valid PEM"])
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception:
        raise ValidationError(["private key is not valid unencrypted PEM"])
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if pub(cert.public_key()) != pub(key.public_key()): raise ValidationError(["private key does not match the certificate"])
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now + timedelta(days=1): raise ValidationError(["certificate is expired or expires within a day"])
    if cert.not_valid_before_utc > now + timedelta(minutes=10): raise ValidationError(["certificate is not valid yet"])
    try: san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: san = []
    missing = [h for h in hostnames[:1] if not any(_matches(p, h) for p in san)]
    if missing: raise ValidationError([f"certificate does not cover {missing[0]} (names: {', '.join(san) or 'none'})"])
    return {"not_after": cert.not_valid_after_utc.isoformat(), "san": san, "self_signed": cert.issuer == cert.subject}


def install(root, sid, cert_pem, key_pem):
    d = _dir(root, sid); d.mkdir(parents=True, exist_ok=True)
    for name, data, mode in (("fullchain.pem", cert_pem, 0o644), ("privkey.pem", key_pem, 0o600)):
        tmp = d / f".{name}.tmp"; tmp.write_text(data); os.chmod(tmp, mode); os.replace(tmp, d / name)


def status(root, sid):
    c = _dir(root, sid) / "fullchain.pem"
    if not c.exists() or not (_dir(root, sid) / "privkey.pem").exists(): return {"installed": False}
    try:
        cert = x509.load_pem_x509_certificate(c.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
        return {"installed": True, "not_after": cert.not_valid_after_utc.isoformat(), "days_left": left, "san": san, "self_signed": cert.issuer == cert.subject}
    except Exception:
        return {"installed": False, "error": "certificate file unreadable"}
