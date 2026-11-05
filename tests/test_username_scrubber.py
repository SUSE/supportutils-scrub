import pytest
from supportutils_scrub.username_scrubber import UsernameScrubber


class TestUsernameScrub:
    def test_username_replaced(self):
        s = UsernameScrubber({"jdoe": "user_0"})
        assert "user_0" in s.scrub("login by jdoe at 10:00")

    def test_system_users_excluded(self):
        excluded = UsernameScrubber.EXCLUDED_USERS
        assert "root" in excluded
        assert "nobody" in excluded
        assert "sshd" in excluded

    def test_empty_dict(self):
        s = UsernameScrubber({})
        assert s.scrub("anything") == "anything"

    def test_consistent(self):
        s = UsernameScrubber({"alice": "user_0"})
        result = s.scrub("alice logged in, alice logged out")
        assert result.count("user_0") == 2

    def test_mapping_property(self):
        s = UsernameScrubber({"x": "y"})
        assert s.mapping == {"x": "y"}


class TestCommonWordNames:
    """An account named like a system directory or a log word is left alone:
    replacing it as a word rewrote /boot/grub2 and "first boot" everywhere."""

    LINE = ("sshd[1234]: pam_unix(sshd:session): session opened for user boot by (uid=0)\n"
            "systemd[1]: Mounting /boot/grub2/i386-pc...\n"
            "Ignition firstboot: first boot of the image\n")

    def test_never_learned_from_a_log(self):
        assert "boot" not in UsernameScrubber.extract_usernames_from_text(self.LINE)
        assert "jdoe" in UsernameScrubber.extract_usernames_from_text(
            "session opened for user jdoe by (uid=0)")

    def test_an_older_mapping_does_not_replace_it(self):
        s = UsernameScrubber({"boot": "user1", "jdoe": "user2"})
        out = s.scrub(self.LINE + "login by jdoe\n")
        assert "/boot/grub2/i386-pc" in out and "first boot" in out
        assert "user1" not in out and "login by user2" in out
