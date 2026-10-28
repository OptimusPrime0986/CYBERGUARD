import pytest
from cyberguard.validation import AdminPolicy, ValidationError, validate_policy, validate_site
from .conftest import site

def mk(**kw): return {**site(), **kw}

def test_valid_site(admin):
    s = validate_site(site(), admin)
    assert s.hostname in s.allowed_hostnames and s.tls_verify is True

@pytest.mark.parametrize("bad", ["Example.com", "a;b.com", "a b.com", "-x.com", "x..com", "a.com\nserver{}", "x" * 300, "", "a/b.com"])
def test_bad_hostnames_rejected(admin, bad):
    with pytest.raises(ValidationError): validate_site(mk(hostname=bad), admin)

@pytest.mark.parametrize("p", [0, 65536, -1, "80", True, None])
def test_bad_ports(admin, p):
    with pytest.raises(ValidationError): validate_site(mk(origin_port=p), admin)

def test_bad_scheme_and_unknown_fields(admin):
    with pytest.raises(ValidationError): validate_site(mk(origin_scheme="ftp"), admin)
    with pytest.raises(ValidationError): validate_site(mk(evil="x"), admin)

@pytest.mark.parametrize("host", ["127.0.0.1", "10.1.2.3", "192.168.0.9", "169.254.169.254", "0.0.0.0", "100.64.0.1"])
def test_ssrf_literal_ips_rejected(host):
    a = AdminPolicy()
    with pytest.raises(ValidationError) as e: validate_site(mk(origin_host=host), a)
    assert "restricted" in str(e.value)

@pytest.mark.parametrize("resolved", [["127.0.0.1"], ["::1"], ["::ffff:127.0.0.1"], ["93.184.216.34", "10.0.0.5"], ["169.254.169.254"]])
def test_ssrf_via_dns_rejected(resolved):
    a = AdminPolicy(resolver=lambda h: resolved)
    with pytest.raises(ValidationError): validate_site(mk(origin_host="evil.example.net"), a)

def test_public_origin_ok_and_explicit_allowances():
    assert validate_site(mk(origin_host="93.184.216.34"), AdminPolicy())
    assert validate_site(mk(origin_host="10.0.0.5"), AdminPolicy(allowed_origin_cidrs=("10.0.0.0/8",)))
    assert validate_site(mk(origin_host="internal-app"), AdminPolicy(allowed_origin_hosts=frozenset({"internal-app"})))

def test_insecure_tls_needs_admin_permission(admin):
    with pytest.raises(ValidationError): validate_site(mk(origin_scheme="https", tls_verify=False), admin)
    ok = AdminPolicy(allowed_origin_hosts=frozenset({"origin"}), allow_insecure_origin_tls=True)
    assert validate_site(mk(origin_scheme="https", tls_verify=False), ok).tls_verify is False

def test_policy_validation():
    assert validate_policy().mode == "blocking"
    for bad in ({"mode": "pause"}, {"max_body_bytes": 0}, {"max_body_bytes": 2**40}, {"allowed_methods": []},
                {"allowed_methods": ["GET", "TRACE"]}, {"paranoia": 4}):
        with pytest.raises(ValidationError): validate_policy(bad)
