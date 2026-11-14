import pytest

from whiff import InvalidOptionError
from whiff.options import LIMIT_CAPS, validate


def test_unknown_option_is_rejected():
    with pytest.raises(InvalidOptionError, match="unknown option"):
        validate({"tokens": 10}, "path")


def test_profile_and_limits():
    opts = validate({"profile": "minimal", "limits": {"max_depth": 0}}, "path")
    assert opts["profile"] == "minimal"
    assert opts["limits"] == {"max_depth": 0}
    with pytest.raises(InvalidOptionError, match="turbo"):
        validate({"profile": "turbo"}, "path")
    with pytest.raises(InvalidOptionError, match="greater than 0"):
        validate({"limits": {"file_timeout_ms": 0}}, "path")
    with pytest.raises(InvalidOptionError, match="exceeds cap"):
        validate({"limits": {"max_depth": LIMIT_CAPS["max_depth"] + 1}}, "path")


def test_hashes_and_name_conflict():
    assert validate({"hashes": ["sha256", "sha256"]}, "path")["hashes"] == ["sha256"]
    with pytest.raises(InvalidOptionError, match="hashes"):
        validate({"hashes": []}, "path")
    with pytest.raises(InvalidOptionError, match="not both"):
        validate({"name": "a.txt", "filename": "b.txt"}, "bytes")


def test_bool_is_not_an_integer_limit():
    with pytest.raises(InvalidOptionError):
        validate({"limits": {"max_depth": True}}, "path")
