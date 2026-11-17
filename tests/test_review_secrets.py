import pytest

from supportutils_scrub.auth_scrubber import AuthScrubber
from supportutils_scrub.cloud_token_scrubber import CloudTokenScrubber
from supportutils_scrub.email_scrubber import EmailScrubber
from supportutils_scrub.ldap_dn_scrubber import LdapDnScrubber
from supportutils_scrub.password_scrubber import PasswordScrubber

# Built at runtime so no string in this file looks like a checked-in secret.
_PW = "Sup3r" + "S3cretValue"


@pytest.mark.parametrize("line", [
    '{"password": "%s"}',
    '<password>%s</password>',
    'db_password=%s',
    'MYSQL_ROOT_PASSWORD=%s',
    'wpa_passphrase=%s',
    'SECRET_KEY=%s',
    'system_token=%s',
    '"Token": "%s"',
    'bindpw %s',
    'ldapsearch -x -D cn=admin,dc=example,dc=com -w %s',
    'ldapsearch --bindpw %s -x',
    'password=%s,uid=1000,vers=3.0',
    'userPassword:: %s',
    'password: {SSHA}%s',
])
def test_secret_key_forms(line):
    out = PasswordScrubber().scrub(line % _PW)
    assert _PW not in out and "scrubbed_pass_" in out


def test_short_and_spaced_values():
    s = PasswordScrubber()
    assert "hunter2" not in s.scrub("password=hunter2")
    out = s.scrub('password = "correct horse battery staple"')
    assert out.startswith('password = "scrubbed_pass_') and out.endswith('"')
    assert "horse" not in out


def test_mount_options_survive():
    out = PasswordScrubber().scrub("username=bob,password=%s,uid=1000,vers=3.0" % _PW)
    assert out.endswith(",uid=1000,vers=3.0")


@pytest.mark.parametrize("line", [
    "sshd: pam_unix(passwd:chauthtok): password changed for jdoe",
    "passwd: password changed.",
    "pam_unix(gdm-password:auth): authentication failure",
    "password=********",
    "password=$DB_PASS",
    "password= *REMOVED BY SUPPORTCONFIG*",
    "password: null",
    "mount -o credentials=/etc/samba/cred.txt,uid=0 //nas/s /mnt",
    "grep -w foo x; ping -w 5 host",
    "ALL=(ALL) NOPASSWD: ALL",
    "passwd: files sss",
    "token: 5000",
    '{"password": "", "user": "bob"}',
    "baseurl=https://updates.example.com/r?credentials=SUSE_x86_64",
])
def test_not_a_secret_is_untouched(line):
    assert PasswordScrubber().scrub(line) == line


_KEY_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "AbCdEfGhIjKl"


def test_aws_json_secret():
    secret = "wJalrXUtnFEMIK7MDENG" + "bPxRfiCYEXAMPLEKEY"
    out = CloudTokenScrubber().scrub('{"SecretAccessKey": "%s"}' % secret)
    assert secret not in out


def test_gcp_private_key_json():
    line = ('"private_key": "-----BEGIN PRIVATE KEY-----\\n%s\\n'
            '-----END PRIVATE KEY-----\\n",' % _KEY_BODY)
    out = CloudTokenScrubber().scrub(line)
    assert _KEY_BODY not in out and out.endswith('",')


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "])
def test_pem_private_key_body(kind):
    text = (f"-----BEGIN {kind}PRIVATE KEY-----\n{_KEY_BODY}\n{_KEY_BODY}\n"
            f"-----END {kind}PRIVATE KEY-----\n")
    out = CloudTokenScrubber().scrub(text)
    assert _KEY_BODY not in out
    assert out.startswith(f"-----BEGIN {kind}PRIVATE KEY-----\nSCRUBBED_PRIVKEY_")
    assert out.endswith(f"\n-----END {kind}PRIVATE KEY-----\n")


def test_certificate_untouched():
    text = f"-----BEGIN CERTIFICATE-----\n{_KEY_BODY}\n-----END CERTIFICATE-----\n"
    assert CloudTokenScrubber().scrub(text) == text


def test_azure_shared_access_key():
    key = "AbCdEfGhIjKlMnOpQrSt" + "UvWxYz0123456789abcdE="
    s = CloudTokenScrubber()
    assert key not in s.scrub(f"Endpoint=sb://ns.example.com/;SharedAccessKey={key}")
    assert key not in s.scrub(f"accountkey={key}")


def test_url_password_with_at_sign():
    out = AuthScrubber().scrub("http_proxy=http://jdoe:P@ssw0rd@203.0.113.9:3128/")
    assert "ssw0rd" not in out and "jdoe" not in out
    assert out.endswith("@203.0.113.9:3128/")


def test_digest_username():
    out = AuthScrubber().scrub('Authorization: Digest username="jdoe", realm="example.com"')
    assert '"jdoe"' not in out and 'realm="example.com"' in out


_SCC = "SCC_" + "0123456789abcdef" * 2


def test_zypp_credentials_in_updates_txt():
    token = "opaque" + "Token0123"
    text = ("#==[ Configuration File ]===========================#\n"
            "# /etc/zypp/credentials.d/SCCcredentials\n"
            f"username={_SCC}\n"
            "password= *REMOVED BY SUPPORTCONFIG*\n"
            f"system_token={token}\n\n"
            "#==[ Configuration File ]===========================#\n"
            "# /etc/zypp/credentials.d/SUSE_Linux_Enterprise_Server_x86_64\n"
            "username=svcuser\n"
            "password= *REMOVED BY SUPPORTCONFIG*\n\n"
            "#==[ Command ]======================================#\n"
            "username=notacredential\n")
    out = PasswordScrubber().scrub(AuthScrubber().scrub(text))
    assert _SCC not in out and token not in out and "svcuser" not in out
    assert out.count("password= *REMOVED BY SUPPORTCONFIG*") == 2
    assert "username=SCRUBBED_LOGIN_1\n" in out
    assert "username=notacredential" in out


def test_scc_login_anywhere_same_pseudonym():
    s = AuthScrubber()
    a = s.scrub(f"Registered as {_SCC}")
    b = s.scrub(f"login: {_SCC}")
    assert _SCC not in a + b and a.split()[-1] == b.split()[-1]


def test_dn_value_with_spaces_and_escapes():
    s = LdapDnScrubber()
    out = s.scrub("dn: CN=John Smith,OU=Payroll Team,DC=corp,DC=test")
    assert "Smith" not in out and "Team" not in out and out.endswith(",DC=corp,DC=test")
    out = s.scrub("CN=Smith\\, John,OU=Users,DC=corp,DC=test")
    assert "Smith" not in out and "John" not in out and ",DC=corp" in out


def test_dn_new_pseudonyms_kept():
    text = "CN=host-1,OU=user3,DC=corp,DC=test"
    assert LdapDnScrubber().scrub(text) == text


@pytest.mark.parametrize("line,addr", [
    ("mail sent to jdoe@corp.example.", "jdoe@corp.example"),
    ("from email_alerts@corp.example", "email_alerts@corp.example"),
    ("cc a@corp.example", "a@corp.example"),
])
def test_email_forms(line, addr):
    assert addr not in EmailScrubber().scrub(line)


def test_email_sentence_dot_kept():
    assert EmailScrubber().scrub("to jdoe@corp.example.").endswith("@scrubbed.local.")


def test_email_pseudonym_untouched():
    for text in ("email_3@scrubbed.local", "SCRUBBED_LOGIN_1@repo.corp.example"):
        assert EmailScrubber().scrub(text) == text
