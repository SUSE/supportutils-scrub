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
