import math

import pytest

from research_lab.canonical import CanonicalError, canonical_json, digest, normalize


def test_sorted_keys_and_compact_separators():
    assert canonical_json({"b": 1, "a": [1, {"d": 2, "c": 3}]}) == '{"a":[1,{"c":3,"d":2}],"b":1}'


def test_nan_is_rejected():
    with pytest.raises(CanonicalError, match="non-finite"):
        canonical_json({"x": math.nan})


@pytest.mark.parametrize("value", [math.inf, -math.inf])
def test_infinity_is_rejected(value):
    with pytest.raises(CanonicalError, match="non-finite"):
        canonical_json([value])


def test_nested_nan_reports_its_path():
    with pytest.raises(CanonicalError, match=r"\$\.a\[1\]\.b"):
        canonical_json({"a": [0, {"b": float("nan")}]})


def test_int_and_float_stay_distinct():
    assert canonical_json({"a": 1}) != canonical_json({"a": 1.0})


def test_strings_are_nfc_normalized():
    decomposed = "é"
    composed = "é"
    assert canonical_json(decomposed) == canonical_json(composed)
    assert normalize({decomposed: 1}) == {composed: 1}


def test_keys_that_collide_after_nfc_are_rejected():
    with pytest.raises(CanonicalError, match="duplicate key"):
        canonical_json({"é": 1, "é": 2})


def test_non_string_keys_are_rejected():
    with pytest.raises(CanonicalError, match="not a string"):
        canonical_json({1: "a"})


@pytest.mark.parametrize("value", [{1, 2}, b"bytes", object(), {"a": object()}])
def test_unsupported_types_are_rejected(value):
    with pytest.raises(CanonicalError, match="not canonical JSON"):
        canonical_json(value)


def test_tuples_become_lists_and_bools_are_kept():
    assert canonical_json((1, True, None)) == "[1,true,null]"


def test_non_ascii_is_escaped():
    assert canonical_json("é") == '"\\u00e9"'


def test_digest_is_full_sha256_and_deterministic():
    first = digest({"k": "v", "n": [1, 2, 3]})
    second = digest({"n": [1, 2, 3], "k": "v"})
    assert first == second
    assert len(first) == 64
    assert all(ch in "0123456789abcdef" for ch in first)
    assert first != digest({"k": "v", "n": [1, 2]})
