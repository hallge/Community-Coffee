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
TYPES = ("key", "coffee", "grinder", "machine", "dialin", "shot", "taste", "service", "service_review", "link")
# A link suggested for the Community Hub (docs/COMMUNITY.md): what it is, and what it is about.
LINK_KINDS = ("video", "playlist", "post", "guide", "article", "podcast")
LINK_TOPICS = ("preparation", "dialing_in", "brewing", "beans", "gear", "milk", "maintenance", "science")
# A coffee rating (docs/COFFEE-TASTE.md in the firmware repository): the cup and the flavour families.
CUP = ("acidity", "sweetness", "body", "bitterness", "finish")
FLAVOURS = ("fruity", "floral", "sweet", "chocolate", "spicy", "roasty", "fermented", "earthy")
MACHINE_STYLES = ("toggle_button", "start_button", "manual", "start_stop_buttons", "hold_button")
# Subscription services (docs/SUBSCRIPTIONS.md in the firmware repository). The lists are the firmware's
# (src/core/Subscriptions.h), in the same order.
SERVICE_KINDS = ("coffee", "supplies", "other")
SERVICE_STYLES = ("single_roaster", "multi_roaster", "curated", "matched", "single_origin", "blends", "decaf",
                  "espresso", "filters", "cleaning", "equipment")
SERVICE_SOURCING = ("fair_trade", "direct_trade", "organic", "farm_named", "prices_published",
                    "sustainable_packaging", "carbon_neutral", "b_corp")
SERVICE_PLATFORMS = ("recharge", "ordergroove", "skio", "loop", "appstle", "bold", "shopify", "own")
SERVICE_ASPECTS = ("value", "quality", "consistency", "reliability", "flexibility", "transparency")
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


DIVISORS = (1, 2, 4, 5, 10, 20, 25, 50, 100)   # core/SettingFormat.h validDivisor


def check_reading(g):
    """How a stored setting is read on this grinder: whole steps, a fraction of a step, or two rings."""
    divisor = g.get("divisor", 1)
    sub_steps = g.get("sub_steps", 0)
    if isinstance(divisor, bool) or divisor not in DIVISORS:
        raise Refused("grinder.divisor is not one the controller offers")
    if isinstance(sub_steps, bool) or not isinstance(sub_steps, int) or not (sub_steps == 0 or 2 <= sub_steps <= 99):
        raise Refused("grinder.sub_steps is outside 2 to 99")
    if sub_steps and divisor != 1:
        raise Refused("a ringed dial has no divisor")


def check_grinder(g):
    check_reading(g)
    _text(g, "unit", 7)
    _text(g, "model", 31, required=False)
    _text(g, "burrs", 23, required=False)
    _number(g, "model_id", 1, 65535, required=False)
    _text(g, "library_id", 39, required=False)
    _number(g, "um_per_unit", 0.01, 1000, required=False)
    _number(g, "calibration", 0, 65535)


def _link(obj, name, required=True):
    """A web link: https, printable, no spaces, at most 199 characters (255 for pictures)."""
    if name not in obj:
        if required:
            raise Refused(f"{name} is missing")
        return
    value = obj[name]
    limit = 255 if name in ("image", "icon") else 199
    if (not isinstance(value, str) or not value.startswith("https://") or len(value) > limit
            or any(ord(c) <= 0x20 or ord(c) > 0x7E for c in value)):
        raise Refused(f"{name} is not an https link of at most {limit} characters")
    # Nothing of one customer's: a shop's general page, not someone's portal, login token or tracking.
    if name in ("image", "icon") or obj.get("t") == "link":  # pictures and Hub links (a video's ?v=) keep a query
        query = value.partition("?")[2].lower()
        if any(word in query for word in ("token", "key=", "sig", "auth", "session", "password")):
            raise Refused(f"{name} carries what looks like a credential")
    else:
        if "?" in value or "#" in value:
            raise Refused(f"{name} has a query or fragment: links are to a shop's general pages")
        path = value[len("https://"):].partition("/")[2]
        for segment in path.split("/"):
            mixed = any(c.isdigit() for c in segment) and any(c.isalpha() for c in segment)
            if "token" in segment.lower() or (len(segment) >= 16 and mixed):
                raise Refused(f"{name} looks like one customer's own link")


def _choices(obj, name, allowed, limit):
    if name not in obj:
        return
    value = obj[name]
    if (not isinstance(value, list) or not value or len(value) > limit or len(set(value)) != len(value)
            or any(v not in allowed for v in value)):
        raise Refused(f"{name} is not a list taken from the controller's own")


def check_service(s, full=True):
    """A subscription service. full: as a controller sends it; else as the library lists it."""
    _text(s, "name", 47)
    _link(s, "url")
    _link(s, "manage_url", required=False)
    if "platform" in s and s["platform"] not in SERVICE_PLATFORMS:
        raise Refused("platform is not one the controller knows")
    if s.get("kind") not in SERVICE_KINDS:
        raise Refused("kind is not coffee, supplies or other")
    ships = s.get("ships_to", [])
    if "ships_to" in s and (not isinstance(ships, list) or not ships or len(ships) > 10 or len(set(ships)) != len(ships)
                            or any(not (isinstance(c, str) and len(c) == 2 and c.isascii() and c.isupper())
                                   for c in ships)):
        raise Refused("ships_to is not a list of two-letter country codes")
    cadences = s.get("cadences", [])
    if "cadences" in s and (not isinstance(cadences, list) or not cadences or len(cadences) > 6
                            or any(isinstance(d, bool) or not isinstance(d, int) or not 1 <= d <= 366 for d in cadences)):
        raise Refused("cadences are not days from 1 to 366")
    if ("price_from_cents" in s) != ("currency" in s):
        raise Refused("a typical price needs its currency, and a currency its price")
    if "price_from_cents" in s:
        _number(s, "price_from_cents", 1, 1000000)
        currency = s["currency"]
        if not (isinstance(currency, str) and len(currency) == 3 and currency.isascii() and currency.isupper()):
            raise Refused("currency is not a three-letter code")
    _choices(s, "style", SERVICE_STYLES, len(SERVICE_STYLES))
    _choices(s, "sourcing", SERVICE_SOURCING, len(SERVICE_SOURCING))
    _link(s, "image", required=False)
    _link(s, "icon", required=False)
    if "color" in s and not (isinstance(s["color"], str) and len(s["color"]) == 7 and s["color"][0] == "#"
                             and all(c in "0123456789abcdefABCDEF" for c in s["color"][1:])):
        raise Refused("color is not #rrggbb")
    _text(s, "about", 160, required=False)
    if full:
        _number(s, "local_id", 1, 65535)
        _number(s, "record", 0, 4294967295)


def check_link(l, full=True):
    """A link for the Community Hub. full: as a controller sends it; else as the library lists it."""
    _link(dict(l, t="link"), "url")
    _text(l, "title", 79)
    if l.get("kind") not in LINK_KINDS:
        raise Refused("kind is not one the controller offers")
    if "topics" not in l:
        raise Refused("topics is missing")
    _choices(l, "topics", LINK_TOPICS, 3)
    _text(l, "why", 160, required=False)
    _link(l, "image", required=False)
    if full:
        _number(l, "local_id", 1, 65535)
        _number(l, "record", 0, 4294967295)


def _service_id(obj, name):
    value = obj.get(name)
    if (not isinstance(value, str) or not value or len(value) > 39
            or any(not (c.islower() or c.isdigit() or c == "-") for c in value)):
        raise Refused(f"{name} is not the id of a listed service")


def check_machine(m, full=True):
    """How an espresso machine is worked. full: a description for the shared list; else as a shot carries it."""
    if m.get("style") not in MACHINE_STYLES:
        raise Refused("machine.style is not one the controller offers")
    _text(m, "maker", 23, required=full)
    _text(m, "model", 31, required=full)
    _text(m, "control", 31, required=full)
    _text(m, "library_id", 39, required=False)
    if "clock_from" in m and m["clock_from"] != "first_drip":
        raise Refused("machine.clock_from is not first_drip")
    if full:
        if "manual_start" in m and m["manual_start"] not in ("tap", "first_drip"):
            raise Refused("manual_start is neither tap nor first_drip")
        for flag in ("hold_preinfusion", "tap_preinfusion", "power_toggle"):
            _number(m, flag, 0, 1)
        _number(m, "self_stop_s", 1, 600, required=False)
        if m["style"] != "toggle_button" and m["hold_preinfusion"]:
            raise Refused("only a button the bot holds can hold pre-infusion")


def check_body(body):
    kind = body.get("t")
    if kind not in TYPES:
        raise Refused(f"unknown record type {kind!r}")
    if body.get("v") != 1:
        raise Refused("unknown record version")
    if kind == "coffee":
        check_coffee(body)
        _number(body, "record", 0, 4294967295)   # which version of it this is, by the sender's count
    elif kind == "grinder":
        # A grinder model described by its owner, for a reviewer.
        _text(body, "model", 31)
        _text(body, "burrs", 23, required=False)
        _text(body, "unit", 7)
        check_reading(body)
        _number(body, "um_per_unit", 0.01, 1000, required=False)
        _number(body, "local_id", 1, 65535)
        _number(body, "record", 0, 4294967295)
    elif kind == "machine":
        # A machine and the rules for working it, set up by its owner, for a reviewer.
        check_machine(body)
        _number(body, "local_id", 1, 65535)
        _number(body, "record", 0, 4294967295)
    elif kind == "dialin":
        check_coffee(body.get("coffee") or {})
        check_recipe(body.get("recipe") or {})
        check_grinder(body.get("grinder") or {})
        _number(body, "grind", 1, 2000)
        _number(body, "frozen_days", 0, 3650, required=False)   # days of the bag's age spent frozen
        result = body.get("result") or {}
        _number(result, "time_s", 5, 90)
        _number(result, "shots", 1, 10)
        if result.get("basis") not in ("total", "pour"):
            raise Refused("result.basis is neither total nor pour")
    elif kind == "service":
        # A subscription service set up by its owner, for a reviewer. Never the owner's own price or dates.
        check_service(body)
    elif kind == "link":
        # A video, post or guide an owner suggests for the Community Hub, for a reviewer.
        check_link(body)
    elif kind == "service_review":
        # How a drinker rated a listed service: stars and aspects. The drinker is a number, never a name.
        _number(body, "id", 1, 4294967295)
        _service_id(body, "service")
        _number(body, "stars", 1, 5)
        _number(body, "drinker", 0, 8)
        aspects = body.get("aspects", {})
        if not isinstance(aspects, dict):
            raise Refused("aspects is not an object")
        for name in aspects:
            if name not in SERVICE_ASPECTS:
                raise Refused(f"aspects.{name} is not one the controller asks for")
            _number(aspects, name, 1, 5)
    elif kind == "taste" and body.get("withdrawn") is True:
        # The owner deleted this rating: it replaces the one with this id, and counts for nothing.
        _number(body, "id", 1, 4294967295)
        extra = set(body) - {"t", "v", "id", "at", "withdrawn"}
        if extra:
            raise Refused(f"a withdrawal holds only its id, not {sorted(extra)}")
    elif kind == "taste":
        # How a drinker liked a coffee (not a shot). The drinker is a number on the controller, never
        # a name. service: the listed subscription service the bag came with, if any.
        if "service" in body:
            _service_id(body, "service")
        coffee = body.get("coffee")
        if not isinstance(coffee, dict):
            raise Refused("coffee is missing")
        check_coffee(coffee, full="local_id" in coffee)
        _number(body, "id", 1, 4294967295)
        _number(body, "stars", 1, 5)
        _number(body, "drinker", 0, 8)
        cup = body.get("cup", {})
        if not isinstance(cup, dict):
            raise Refused("cup is not an object")
        for name in cup:
            if name not in CUP:
                raise Refused(f"cup.{name} is not one the controller asks for")
            _number(cup, name, 1, 5)
        flavours = body.get("flavours", [])
        if (not isinstance(flavours, list) or any(f not in FLAVOURS for f in flavours)
                or len(set(flavours)) != len(flavours)):
            raise Refused("flavours are not the controller's flavour families")
    elif kind == "shot":
        if "coffee" in body:
            check_coffee(body["coffee"], full="local_id" in body["coffee"])
        check_recipe(body.get("recipe") or {})
        check_grinder(body.get("grinder") or {})
        _number(body, "grind", 1, 2000, required=False)
        _number(body, "frozen_days", 0, 3650, required=False)
        result = body.get("result") or {}
        _number(result, "yield_g", 0, 1000)
        _number(result, "time_s", 0, 90)
        _number(result, "pour_flow_gs", 0, 100, required=False)
        _number(result, "ratio", 0, 40, required=False)      # yield over dose, as brewed
        if "machine" in body:
            check_machine(body["machine"], full=False)
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
    try:
        kind = check_body(body)
    except Refused as error:
        # Signed by a key on file, refused for what it says: who sent it is known, so the refusal can
        # be reported back to that controller (intake.py tell_refused).
        error.kid, error.body = kid, body
        raise
    return kind, kid, body


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
    # How the setting is read: whole steps unless the grinder says otherwise.
    assert verify(envelope(dialin.replace('"unit":"um"', '"unit":"dial","divisor":10')), keys)[0] == "dialin"
    assert verify(envelope(dialin.replace('"unit":"um"', '"unit":"sette","sub_steps":9')), keys)[0] == "dialin"
    assert "divisor" in refused(envelope(dialin.replace('"unit":"um"', '"unit":"dial","divisor":3')))
    assert "sub_steps" in refused(envelope(dialin.replace('"unit":"um"', '"unit":"dial","sub_steps":1')))
    assert "no divisor" in refused(envelope(dialin.replace('"unit":"um"', '"unit":"dial","sub_steps":9,"divisor":10')))
    # Days in the freezer: optional, a count of days.
    assert verify(envelope(dialin.replace('"grind":246', '"frozen_days":30,"grind":246')), keys)[0] == "dialin"
    assert "outside" in refused(envelope(dialin.replace('"grind":246', '"frozen_days":-1,"grind":246')))
    grinder = '{"t":"grinder","v":1,"record":3,"local_id":2,"model":"Home Built 64","unit":"dial"}'
    assert verify(envelope(grinder), keys)[0] == "grinder"
    assert "unit is missing" in refused(envelope(grinder.replace(',"unit":"dial"', "")))
    assert "unknown record type" in refused(envelope('{"t":"other","v":1}'))
    # A link for the Community Hub.
    link = ('{"t":"link","v":1,"record":5,"local_id":2,"url":"https://www.youtube.com/watch?v=aTFsBqhpLes",'
            '"title":"Understanding Espresso - Dose","kind":"video","topics":["dialing_in"],"why":"Dose, explained"}')
    assert verify(envelope(link), keys)[0] == "link"
    assert "https" in refused(envelope(link.replace("https://www.youtube", "http://www.youtube")))
    assert "topics" in refused(envelope(link.replace('["dialing_in"]', '["cats"]')))
    assert "topics is missing" in refused(envelope(link.replace(',"topics":["dialing_in"]', '')))
    assert "kind" in refused(envelope(link.replace('"video"', '"meme"')))
    # A deleted rating, withdrawn: its id and nothing about the coffee or the drinker.
    withdrawn = '{"t":"taste","v":1,"id":42,"at":"2026-10-26T10:00:00Z","withdrawn":true}'
    assert verify(envelope(withdrawn), keys)[0] == "taste"
    assert "only its id" in refused(envelope(withdrawn.replace('"withdrawn"', '"stars":5,"withdrawn"')))
    assert "missing" in refused(envelope('{"t":"coffee","v":1,"local_id":4,"record":7}'))
    assert "record is missing" in refused(envelope(coffee.replace('"record":7,', '')))
    # A subscription service, and a review of one.
    service = ('{"t":"service","v":1,"record":41,"local_id":3,"name":"Trade Coffee","url":"https://www.drinktrade.com/",'
               '"manage_url":"https://www.drinktrade.com/account","platform":"ordergroove","kind":"coffee",'
               '"ships_to":["US"],"cadences":[14,28],"price_from_cents":1500,"currency":"USD",'
               '"style":["multi_roaster","matched"],"sourcing":["fair_trade"],"color":"#aa3311"}')
    assert verify(envelope(service), keys)[0] == "service"
    assert "https" in refused(envelope(service.replace('"https://www.drinktrade.com/account"', '"javascript:x"')))
    assert "country" in refused(envelope(service.replace('["US"]', '["usa"]')))
    assert "controller's own" in refused(envelope(service.replace('"fair_trade"', '"free_beer"')))
    assert "currency" in refused(envelope(service.replace(',"currency":"USD"', "")))
    assert "kind" in refused(envelope(service.replace('"kind":"coffee"', '"kind":"wine"')))
    review = ('{"t":"service_review","v":1,"id":7,"service":"trade-coffee","drinker":2,"stars":5,'
              '"aspects":{"value":4,"consistency":5}}')
    assert "query" in refused(envelope(service.replace('"https://www.drinktrade.com/account"',
                                                        '"https://www.drinktrade.com/account?ref=me"')))
    assert "own link" in refused(envelope(service.replace(
        '"https://www.drinktrade.com/account"',
        '"https://shop.example/tools/recurring/portal/0123456789abcdef0123456789ab/subscriptions"')))
    assert verify(envelope(service.replace('"https://www.drinktrade.com/account"',
                                           '"https://shopify.com/12345678901/account/orders"')), keys)[0] == "service"
    assert "credential" in refused(envelope(service.replace('"color":"#aa3311"',
                                                            '"color":"#aa3311","image":"https://x.example/i.png?token=abc"')))
    assert verify(envelope(service.replace('"color":"#aa3311"',
                                           '"color":"#aa3311","image":"https://x.example/i.png?v=17&width=1200"')), keys)[0] == "service"
    assert verify(envelope(review), keys)[0] == "service_review"
    assert "aspects.speed" in refused(envelope(review.replace('"value":4', '"speed":4')))
    assert "listed service" in refused(envelope(review.replace('"trade-coffee"', '"Trade Coffee"')))
    taste = ('{"t":"taste","v":1,"id":3,"coffee":{"name":"Alma"},"service":"trade-coffee","drinker":0,'
             '"stars":4,"cup":{},"flavours":[]}')
    assert verify(envelope(taste), keys)[0] == "taste"
    assert "listed service" in refused(envelope(taste.replace('"trade-coffee"', '"../x"')))
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
