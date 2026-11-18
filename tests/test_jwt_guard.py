import json

import pytest

import jwt_guard as jg

SECRET = "correct horse battery staple"


def test_1_alg_none_is_rejected():
    token = jg.encode({"sub": "alice"}, alg="none")
    with pytest.raises(ValueError):
        jg.decode(token, SECRET)


def test_2_tampered_payload_is_rejected():
    token = jg.encode({"sub": "alice"}, SECRET)
    parts = token.split(".")
    tampered = jg._b64encode(json.dumps({"sub": "bob"}, separators=(",", ":")).encode())
    with pytest.raises(ValueError):
        jg.decode(f"{parts[0]}.{tampered}.{parts[2]}", SECRET)


def test_3_expired_token_is_rejected():
    token = jg.encode({"sub": "alice", "exp": 1000}, SECRET)
    with pytest.raises(ValueError):
        jg.decode(token, SECRET, now=2000)


def test_4_not_before_in_future_is_rejected():
    token = jg.encode({"sub": "alice", "nbf": 2000}, SECRET)
    with pytest.raises(ValueError):
        jg.decode(token, SECRET, now=1000)


def test_5_issuer_mismatch_is_rejected():
    token = jg.encode({"sub": "alice", "iss": "other"}, SECRET)
    with pytest.raises(ValueError):
        jg.decode(token, SECRET, issuer="expected")


def test_6_audience_mismatch_is_rejected():
    token = jg.encode({"sub": "alice", "aud": "other"}, SECRET)
    with pytest.raises(ValueError):
        jg.decode(token, SECRET, audience="expected")


def test_7_empty_secret_is_rejected():
    token = jg.encode({"sub": "alice"}, "")
    with pytest.raises(ValueError):
        jg.decode(token, "")


def test_8_short_secret_is_rejected():
    token = jg.encode({"sub": "alice"}, "x")
    with pytest.raises(ValueError):
        jg.decode(token, "x")


def test_9_algorithm_not_allowed_is_rejected():
    token = jg.encode({"sub": "alice"}, SECRET, alg="HS512")
    with pytest.raises(ValueError):
        jg.decode(token, SECRET, algorithms=("HS256",))


def test_10_malformed_token_is_rejected():
    one_part = jg._b64encode(b'{"alg":"HS256"}')
    with pytest.raises(ValueError):
        jg.decode(one_part, SECRET)


def test_11_non_string_token_is_rejected():
    with pytest.raises(ValueError):
        jg.decode(123, SECRET)


def test_12_invalid_encoding_is_rejected():
    with pytest.raises(ValueError, match="invalid token"):
        jg.decode("!!!.???.xxx", SECRET)


def test_13_kid_traversal_is_rejected():
    token = jg.encode({"sub": "alice"}, SECRET, kid="../secret")
    with pytest.raises(ValueError):
        jg.decode(token, SECRET)


def test_14_non_jwt_typ_is_rejected():
    header = jg._b64encode(json.dumps({"alg": "HS256", "typ": "JWT2"}, separators=(",", ":")).encode())
    body = jg._b64encode(json.dumps({"sub": "alice"}, separators=(",", ":")).encode())
    with pytest.raises(ValueError):
        jg.decode(f"{header}.{body}.", SECRET)


def test_15_missing_exp_is_rejected_when_required():
    token = jg.encode({"sub": "alice"}, SECRET)
    with pytest.raises(ValueError):
        jg.decode(token, SECRET, require_exp=True)
