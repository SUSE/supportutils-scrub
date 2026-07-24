import pytest
from supportutils_scrub.password_scrubber import PasswordScrubber


def _make():
    return PasswordScrubber(mappings={})


class TestPasswordScrub:
    def test_password_equals(self):
        s = _make()
        result = s.scrub('password=MySecret123')
        assert "MySecret123" not in result
        assert "scrubbed_pass_" in result

    def test_passwd_equals(self):
        s = _make()
        result = s.scrub('passwd = "longpassword"')
        assert "longpassword" not in result

    def test_short_password_not_matched(self):
        s = _make()
        result = s.scrub("password=short")
        # "short" is < 8 chars, regex requires 8+
        assert "short" in result

    def test_already_scrubbed_skipped(self):
        s = _make()
        text = "password=scrubbed_pass_1"
        assert s.scrub(text) == text

    def test_removed_marker_skipped(self):
        s = _make()
        text = "password=*REMOVED*"
        assert "*REMOVED" in s.scrub(text)

    def test_mapping_populated(self):
        s = _make()
        s.scrub("password=SuperSecret1")
        assert "SuperSecret1" in s.mapping

    def test_password_colon_yaml(self):
        s = _make()
        out = s.scrub("password: YamlSecret1")
        assert "YamlSecret1" not in out
        assert "scrubbed_pass_" in out

    def test_passwd_colon_netrc(self):
        s = _make()
        out = s.scrub('passwd: "NetrcPass1"')
        assert "NetrcPass1" not in out

    def test_password_colon_quoted(self):
        s = _make()
        out = s.scrub('password: "AnsiblePass1"')
        assert "AnsiblePass1" not in out


class TestCliSecretScrub:
    def test_gpg_passphrase_space_form(self):
        s = _make()
        out = s.scrub("gpg --batch --passphrase Hunter2secret --sign a.txt")
        assert "Hunter2secret" not in out
        assert "--passphrase scrubbed_pass_" in out

    def test_passphrase_equals_form(self):
        s = _make()
        out = s.scrub("openssl enc --passphrase=S3cr3t!x")
        assert "S3cr3t!x" not in out

    def test_quoted_value_with_spaces(self):
        s = _make()
        out = s.scrub('gpg --passphrase "my secret phrase" file')
        assert "my secret phrase" not in out
        assert '--passphrase "scrubbed_pass_' in out

    def test_credentials_equals(self):
        s = _make()
        out = s.scrub("mount -o credentials=RealCifsPw1,rw //srv/share /mnt")
        assert "RealCifsPw1" not in out
        assert ",rw" in out

    def test_following_flag_untouched(self):
        s = _make()
        text = "gpg --password --stdin"
        assert s.scrub(text) == text

    def test_shell_var_untouched(self):
        s = _make()
        text = "gpg --passphrase $GPGPASS file"
        assert s.scrub(text) == text

    def test_placeholder_untouched(self):
        s = _make()
        text = "gpg --passphrase <passphrase> file"
        assert s.scrub(text) == text

    def test_password_file_option_untouched(self):
        s = _make()
        text = "tool --password-file /etc/secret"
        assert s.scrub(text) == text

    def test_flag_cluster_untouched(self):
        s = _make()
        text = "ss -plnt ; tar -pxvf a.tar ; mkdir -p /tmp/x"
        assert s.scrub(text) == text

    def test_passphrase_config_form(self):
        s = _make()
        out = s.scrub("passphrase: LongSecret99")
        assert "LongSecret99" not in out

    def test_same_value_same_token(self):
        s = _make()
        out = s.scrub("password=RepeatMe123 and --password RepeatMe123")
        assert out.count("scrubbed_pass_1") == 2

    def test_ocr_ps_output_line(self):
        s = _make()
        out = s.scrub("user 4242 0.0 gpg --pinentry-mode loopback --passphrase Tr0ub4dor&3 -d backup.gpg")
        assert "Tr0ub4dor" not in out
