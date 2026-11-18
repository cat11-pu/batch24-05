import base64
import hashlib
import hmac
import json
import time


def _b64encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def encode(payload, secret="", alg="HS256", kid=None):
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    head = _b64encode(json.dumps(header, separators=(",", ":")).encode())
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signing = f"{head}.{body}"
    if alg == "none":
        return f"{signing}."
    signature = hmac.new(secret.encode(), signing.encode(), hashlib.sha256).digest()
    return f"{signing}.{_b64encode(signature)}"


def decode(token, secret="", algorithms=("HS256",), issuer=None, audience=None, now=None, require_exp=False):
    parts = token.split(".")
    header = json.loads(_b64decode(parts[0]))
    payload = json.loads(_b64decode(parts[1]))
    return payload
