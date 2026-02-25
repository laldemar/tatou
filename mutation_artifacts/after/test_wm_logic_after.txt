import os
import pytest

import server.src.wm_logic as m
print("MODULE USED:", m.__name__)

from server.src.wm_logic import (
    WatermarkLogicError,
    validate_method_name,
    validate_secret_and_key,
    resolve_method,
)


def test_mutmut_forced_fail():
    if os.environ.get("MUTANT_UNDER_TEST") == "fail":
        pytest.fail("Forced failure for mutmut sanity check")


# -------------------------
# validate_method_name
# -------------------------

def test_validate_method_name_valid():
    validate_method_name("method")


@pytest.mark.parametrize("bad", [None, "", 123, True])
def test_validate_method_name_invalid(bad):
    with pytest.raises(WatermarkLogicError):
        validate_method_name(bad)


def test_validate_method_name_whitespace():
    # stronger behavioural check
    with pytest.raises(WatermarkLogicError):
        validate_method_name("   ")


# -------------------------
# validate_secret_and_key
# -------------------------

def test_validate_secret_and_key_valid():
    validate_secret_and_key("secret", "key")


@pytest.mark.parametrize(
    "secret,key",
    [
        (None, "key"),
        ("secret", None),
        ("", "key"),
        ("secret", ""),
        ("   ", "key"),     # added edge case
        ("secret", "   "),  # added edge case
    ],
)
def test_validate_secret_and_key_invalid(secret, key):
    with pytest.raises(WatermarkLogicError):
        validate_secret_and_key(secret, key)


def test_validate_secret_and_key_type_strictness():
    # ensures logical mutations in isinstance checks are caught
    with pytest.raises(WatermarkLogicError):
        validate_secret_and_key(123, "key")

    with pytest.raises(WatermarkLogicError):
        validate_secret_and_key("secret", 456)


# -------------------------
# resolve_method
# -------------------------

def test_resolve_method_valid():
    obj = object()
    registry = {"a": obj}

    result = resolve_method(registry, "a")

    # explicit behavioural assertion
    assert result is obj


def test_resolve_method_unknown():
    registry = {"a": object()}
    with pytest.raises(WatermarkLogicError):
        resolve_method(registry, "b")


def test_resolve_method_invalid_name():
    registry = {"a": object()}
    with pytest.raises(WatermarkLogicError):
        resolve_method(registry, None)


def test_resolve_method_registry_not_modified():
    # ensures mutations affecting return logic are detected
    obj = object()
    registry = {"a": obj}

    resolve_method(registry, "a")

    assert registry["a"] is obj