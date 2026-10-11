#!/usr/bin/env python3
"""Check records sent by Brew by Weight controllers before they are used.

    python tools/verify_record.py --keys <folder of key records> <record.json> ...
    python tools/verify_record.py --self-test

A record is the envelope written by the firmware (src/core/Share.h):

    {"v":1,"kid":"<key id>","alg":"ES256","sig":"<base64 r|s>","body":"{...}"}

For each one this checks, in order:
  1. the envelope's shape, and that "body" is itself JSON with a known type;
  2. that the key it names is on file (keys/<kid>.json), or, for a key
     record, that the id is really the fingerprint of the key it carries;
  3. the signature: ECDSA P-256 over SHA-256 of the body exactly as it
     stands in the envelope;
  4. that the values are in the ranges the firmware allows.

Anything not signed with ES256 is refused. That includes what the PC
emulator writes ("EMULATOR-UNSIGNED"): it has no real key.

Needs only Python 3.8 or later. Verification involves no secret, so a plain
implementation is enough; nothing here should ever be used to sign.

Exit status: 0 if every record passed, 1 otherwise.
"""
import argparse
import base64
import hashlib
import json
import os
import sys

# ---- P-256 ------------------------------------------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0]:
        if (p[1] + q[1]) % P == 0:
            return None
        m = (3 * p[0] * p[0] + A) * pow(2 * p[1], -1, P) % P
    else:
        m = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (m * m - p[0] - q[0]) % P
    return x, (m * (p[0] - x) - p[1]) % P


def _mul(k, point):
    result = None
    while k:
        if k & 1:
            result = _add(result, point)
        point = _add(point, point)
        k >>= 1
    return result


def on_curve(point):
    x, y = point
    return 0 < x < P and 0 < y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def ecdsa_verify(public, digest, r, s):
    """public: (x, y); digest: 32 bytes; r, s: integers."""
    if not on_curve(public) or not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(digest, "big")
    w = pow(s, -1, N)
    point = _add(_mul(e * w % N, G), _mul(r * w % N, public))
    return point is not None and point[0] % N == r


# ---- records ----------------------------------------------------------------
TYPES = ("key", "coffee", "dialin", "shot")
KEY_ID_HEX = 20


class Refused(Exception):
    pass


def key_id(public_bytes):
    return hashlib.sha256(public_bytes).hexdigest()[:KEY_ID_HEX]


def parse_public(b64):
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        raise Refused("public key is not base64")
    if len(raw) != 65 or raw[0] != 4:
        raise Refused("public key is not an uncompressed P-256 point")
    point = int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
    if not on_curve(point):
        raise Refused("public key is not a point on P-256")
    return raw, point


def _number(obj, name, lo, hi, required=True):
    if name not in obj:
        if required:
            raise Refused(f"{name} is missing")
        return
    value = obj[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not lo <= value <= hi:
        raise Refused(f"{name} = {value!r} is outside {lo} to {hi}")


def _text(obj, name, limit, required=True):
    if name not in obj:
        if required:
            raise Refused(f"{name} is missing")
        return
    value = obj[name]
    if not isinstance(value, str) or not value or len(value) > limit:
        raise Refused(f"{name} is not text of 1 to {limit} characters")
    if any(ord(c) < 0x20 or ord(c) > 0x7E for c in value):
        raise Refused(f"{name} has characters the controller cannot have sent")


def check_coffee(c, full=True):
    _text(c, "name", 23)
    for name, limit in (("roaster", 23), ("origin", 23), ("region", 31), ("producer", 31),
                        ("varietal", 31), ("process", 15), ("notes", 47)):
        _text(c, name, limit, required=False)
    if "roast_level" in c and c["roast_level"] not in (
            "light", "medium-light", "medium", "medium-dark", "dark"):
        raise Refused("roast_level is not one the controller offers")
    _number(c, "altitude_m", 1, 4000, required=False)
    _text(c, "library_id", 39, required=False)
    if full:
        _number(c, "local_id", 1, 65535)


def check_recipe(r):
    _number(r, "dose_g", 5, 30)          # MIN_DOSE_G .. MAX_DOSE_G
    _number(r, "yield_g", 5, 200)        # MIN_TARGET_G .. MAX_TARGET_G
    _number(r, "target_time_s", 5, 60, required=False)
    _number(r, "preinfusion_hold_s", 0.3, 30, required=False)
    _number(r, "bloom_pause_s", 1, 45, required=False)


def check_grinder(g):
    _text(g, "unit", 7)
    _text(g, "model", 31, required=False)
    _text(g, "burrs", 23, required=False)
    _number(g, "model_id", 1, 65535, required=False)
    _number(g, "um_per_unit", 0.01, 1000, required=False)
    _number(g, "calibration", 0, 65535)


def check_body(body):
    kind = body.get("t")
    if kind not in TYPES:
        raise Refused(f"unknown record type {kind!r}")
    if body.get("v") != 1:
        raise Refused("unknown record version")
    if kind == "coffee":
        check_coffee(body)
        _number(body, "record", 0, 4294967295)   # which version of it this is, by the sender's count
    elif kind == "dialin":
        check_coffee(body.get("coffee") or {})
        check_recipe(body.get("recipe") or {})
        check_grinder(body.get("grinder") or {})
        _number(body, "grind", 1, 2000)
        result = body.get("result") or {}
        _number(result, "time_s", 5, 90)
        _number(result, "shots", 1, 10)
        if result.get("basis") not in ("total", "pour"):
            raise Refused("result.basis is neither total nor pour")
    elif kind == "shot":
        if "coffee" in body:
            check_coffee(body["coffee"], full="local_id" in body["coffee"])
        check_recipe(body.get("recipe") or {})
        check_grinder(body.get("grinder") or {})
        _number(body, "grind", 1, 2000, required=False)
        result = body.get("result") or {}
        _number(result, "yield_g", 0, 1000)
        _number(result, "time_s", 0, 90)
        _number(result, "pour_flow_gs", 0, 100, required=False)
    return kind


def verify(envelope_text, keys):
    """keys: {kid: (x, y)}. Returns (type, kid, body). Raises Refused."""
    try:
        envelope = json.loads(envelope_text)
    except ValueError:
        raise Refused("not JSON")
    if not isinstance(envelope, dict) or envelope.get("v") != 1:
        raise Refused("not a version 1 envelope")
    kid, alg, sig, body_text = (envelope.get(k) for k in ("kid", "alg", "sig", "body"))
    if not all(isinstance(v, str) for v in (kid, alg, sig, body_text)):
        raise Refused("kid, alg, sig and body must all be text")
    if alg != "ES256":
        raise Refused(f"signed with {alg!r}, not ES256: not a signature this library accepts")
    try:
        body = json.loads(body_text)
    except ValueError:
        raise Refused("body is not JSON")
    if not isinstance(body, dict):
        raise Refused("body is not an object")
    if body.get("t") == "key":
        # A key vouches for itself: its id must be its own fingerprint.
        if body.get("alg") != "ES256":
            raise Refused("key record for another algorithm")
        raw, public = parse_public(body.get("key", ""))
        if key_id(raw) != kid:
            raise Refused("key id is not the fingerprint of the key it carries")
    else:
        public = keys.get(kid)
        if public is None:
            raise Refused(f"key {kid} is not on file")
    try:
        raw_sig = base64.b64decode(sig, validate=True)
    except Exception:
        raise Refused("signature is not base64")
    if len(raw_sig) != 64:
        raise Refused("signature is not 64 bytes")
    digest = hashlib.sha256(body_text.encode("utf-8")).digest()
    if not ecdsa_verify(public, digest, int.from_bytes(raw_sig[:32], "big"),
                        int.from_bytes(raw_sig[32:], "big")):
        raise Refused("signature does not match")
    return check_body(body), kid, body


def load_keys(folder):
    """Key records already accepted: keys/<kid>.json. Each is checked again."""
    keys = {}
    if not folder or not os.path.isdir(folder):
        return keys
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                _, kid, body = verify(f.read(), {})
            keys[kid] = parse_public(body["key"])[1]
        except (Refused, OSError, KeyError) as error:
            print(f"key file {name} ignored: {error}", file=sys.stderr)
    return keys


# ---- self-test ----------------------------------------------------------------
def self_test():
    # RFC 6979, appendix A.2.5: P-256 with SHA-256.
    public = (0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6,
              0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299)
    private = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    assert on_curve(G) and _mul(N, G) is None
    assert _mul(private, G) == public
    r = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    s = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8
    digest = hashlib.sha256(b"sample").digest()
    assert ecdsa_verify(public, digest, r, s)
    assert not ecdsa_verify(public, hashlib.sha256(b"sample.").digest(), r, s)
    assert not ecdsa_verify(public, digest, r, s ^ 1)

    # An envelope as the firmware writes it, signed here for the test only.
    def sign(body_text, k=0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF):
        e = int.from_bytes(hashlib.sha256(body_text.encode()).digest(), "big")
        rr = _mul(k, G)[0] % N
        ss = pow(k, -1, N) * (e + rr * private) % N
        return base64.b64encode(rr.to_bytes(32, "big") + ss.to_bytes(32, "big")).decode()

    raw = b"\x04" + public[0].to_bytes(32, "big") + public[1].to_bytes(32, "big")
    kid = key_id(raw)

    def envelope(body_text, alg="ES256", who=kid):
        return json.dumps({"v": 1, "kid": who, "alg": alg, "sig": sign(body_text),
                           "body": body_text}, separators=(",", ":"))

    key_body = json.dumps({"t": "key", "v": 1, "alg": "ES256",
                           "key": base64.b64encode(raw).decode()}, separators=(",", ":"))
    assert verify(envelope(key_body), {})[0] == "key"
    keys = {kid: public}
    coffee = '{"t":"coffee","v":1,"local_id":4,"record":7,"name":"Idjwi Island","roaster":"Portrait"}'
    assert verify(envelope(coffee), keys)[0] == "coffee"
    dialin = ('{"t":"dialin","v":1,"coffee":{"local_id":4,"name":"Idjwi Island"},'
              '"recipe":{"dose_g":18,"yield_g":36,"target_time_s":26},'
              '"grinder":{"model_id":1,"unit":"um","um_per_unit":1,"calibration":0},'
              '"grind":246,"result":{"time_s":25.6,"basis":"total","shots":3}}')
    assert verify(envelope(dialin), keys)[0] == "dialin"

    def refused(text, known=keys):
        try:
            verify(text, known)
        except Refused as error:
            return str(error)
        raise AssertionError("accepted: " + text[:80])

    assert "not on file" in refused(envelope(coffee), {})
    assert "does not match" in refused(envelope(coffee).replace("Idjwi", "Idjwj"))
    assert "not ES256" in refused(envelope(coffee, alg="EMULATOR-UNSIGNED"))
    assert "fingerprint" in refused(envelope(key_body, who="0" * 20), {})
    assert "outside" in refused(envelope(dialin.replace('"dose_g":18', '"dose_g":180')))
    assert "unknown record type" in refused(envelope('{"t":"other","v":1}'))
    assert "missing" in refused(envelope('{"t":"coffee","v":1,"local_id":4,"record":7}'))
    assert "record is missing" in refused(envelope(coffee.replace('"record":7,', '')))
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--keys", help="folder of accepted key records")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("records", nargs="*")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    keys = load_keys(args.keys)
    failed = 0
    for path in args.records:
        try:
            with open(path, encoding="utf-8") as f:
                kind, kid, _ = verify(f.read(), keys)
            print(f"ok       {path}  ({kind}, key {kid})")
        except Refused as error:
            failed += 1
            print(f"REFUSED  {path}  {error}")
        except OSError as error:
            failed += 1
            print(f"REFUSED  {path}  cannot be read: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
