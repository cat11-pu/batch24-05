import base64
import hashlib
import hmac
import json
import math
import re
import time


MIN_SECRET_BYTES = 16

_HMAC_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _invalid(reason="malformed token"):
    raise ValueError(f"invalid token: {reason}")


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    if not isinstance(text, str) or not _B64URL_RE.fullmatch(text):
        _invalid("invalid base64url")
    if len(text) % 4 == 1:
        _invalid("invalid base64url length")
    try:
        return base64.b64decode(
            (text + "=" * (-len(text) % 4)).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except Exception:
        _invalid("invalid base64url")


def _reject_constant(_value):
    _invalid("invalid JSON constant")


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _invalid("duplicate JSON key")
        result[key] = value
    return result


def _decode_json_segment(segment, name):
    try:
        raw = _b64decode(segment)
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
        )
    except Exception:
        _invalid(f"invalid {name}")
    if not isinstance(value, dict):
        _invalid(f"{name} must be a JSON object")
    return value


def _secret_bytes(secret):
    if isinstance(secret, str):
        data = secret.encode("utf-8")
    elif isinstance(secret, bytes):
        data = secret
    else:
        _invalid("secret must be a string or bytes")
    if len(data) < MIN_SECRET_BYTES:
        _invalid("secret is too short")
    return data


def _normalize_algorithms(algorithms):
    if algorithms is None:
        _invalid("algorithms must be provided")
    if isinstance(algorithms, str):
        algorithms = (algorithms,)
    try:
        allowed = set(algorithms)
    except TypeError:
        _invalid("algorithms must be iterable")
    if not allowed or not all(isinstance(alg, str) for alg in allowed):
        _invalid("algorithms must contain algorithm names")
    return allowed


def _validate_header(header, allowed_algorithms):
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed_algorithms:
        _invalid("algorithm is not allowed")
    if alg not in _HMAC_ALGORITHMS:
        _invalid("unsupported algorithm")

    if "typ" in header and header["typ"] != "JWT":
        _invalid("unexpected token type")

    if "kid" in header:
        kid = header["kid"]
        if (
            not isinstance(kid, str)
            or not kid
            or len(kid) > 256
            or kid in (".", "..")
            or not _KID_RE.fullmatch(kid)
        ):
            _invalid("invalid kid")

    return alg


def _numeric_claim(payload, name):
    if name not in payload:
        return None
    value = payload[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _invalid(f"{name} must be numeric")
    if isinstance(value, float) and not math.isfinite(value):
        _invalid(f"{name} must be finite")
    return value


def _validate_claims(payload, issuer, audience, current_time, require_exp):
    exp = _numeric_claim(payload, "exp")
    nbf = _numeric_claim(payload, "nbf")
    _numeric_claim(payload, "iat")

    if require_exp and exp is None:
        _invalid("exp is required")
    if exp is not None and current_time >= exp:
        _invalid("token has expired")
    if nbf is not None and current_time < nbf:
        _invalid("token is not yet valid")

    if "iss" in payload:
        if not isinstance(payload["iss"], str):
            _invalid("iss must be a string")
        if issuer is not None and payload["iss"] != issuer:
            _invalid("issuer mismatch")

    if issuer is not None:
        if not isinstance(issuer, str):
            _invalid("issuer must be a string")
        if "iss" not in payload:
            _invalid("issuer mismatch")

    aud = payload.get("aud")
    if "aud" in payload:
        if isinstance(aud, str):
            aud_values = [aud]
        elif isinstance(aud, list) and aud and all(isinstance(item, str) for item in aud):
            aud_values = aud
        else:
            _invalid("aud must be a string or a non-empty list of strings")
    else:
        aud_values = None

    if audience is not None:
        if not isinstance(audience, str):
            _invalid("audience must be a string")
        if aud_values is None or audience not in aud_values:
            _invalid("audience mismatch")


def decode(
    token,
    secret="",
    algorithms=("HS256",),
    issuer=None,
    audience=None,
    now=None,
    require_exp=False,
):
    if not isinstance(token, str):
        _invalid("token must be a string")
    if token.count(".") != 2:
        _invalid("token must have three segments")

    parts = token.split(".")
    if any(not part for part in parts):
        _invalid("token segments must not be empty")

    key = _secret_bytes(secret)
    allowed_algorithms = _normalize_algorithms(algorithms)

    header = _decode_json_segment(parts[0], "header")
    payload = _decode_json_segment(parts[1], "payload")
    alg = _validate_header(header, allowed_algorithms)

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected_signature = hmac.new(key, signing_input, _HMAC_ALGORITHMS[alg]).digest()
    signature = _b64decode(parts[2])
    if len(signature) != len(expected_signature) or not hmac.compare_digest(
        signature, expected_signature
    ):
        _invalid("signature mismatch")

    if now is None:
        current_time = time.time()
    elif isinstance(now, bool) or not isinstance(now, (int, float)):
        _invalid("now must be numeric")
    else:
        current_time = now
    if isinstance(current_time, float) and not math.isfinite(current_time):
        _invalid("now must be finite")

    _validate_claims(payload, issuer, audience, current_time, require_exp)
    return payload


def encode(payload, secret="", alg="HS256", kid=None):
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    head = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{head}.{body}"
    if alg == "none":
        return f"{signing}."
    digestmod = _HMAC_ALGORITHMS.get(alg, hashlib.sha256)
    sig_secret = secret.encode() if isinstance(secret, str) else secret
    signature = hmac.new(sig_secret, signing.encode(), digestmod).digest()
    return f"{signing}.{_b64encode(signature)}"
