#!/usr/bin/env python3
"""Build the library's index from the records contributors have sent.

    python tools/build_index.py --root <library folder>
    python tools/build_index.py --self-test
    python tools/build_index.py --make-example <new folder>

Reads, under the root:
    keys/<key id>.json                  contributors' public keys
    dialins/**/*.json                   settled dial-ins (signed records)
    status/<key id>.json                which of a contributor's coffees are published, and as what
    catalog/**/*.json                   the published coffees, one file each: {"id": "roaster/name", ...}

Writes, under root/index:
    coffees.json                        every published coffee, for searching
    dialin/<coffee file>.json           what contributors settled on for one coffee
    fit/<key id>.json                   how each contributor's grinder sits against the common scale

The fit (docs/COMMUNITY.md, section 6). Every dial-in says: on this grinder,
this coffee with this recipe settled at this setting. Settings on different
grinders do not compare directly, so the model is

    setting = scale(grinder) x fineness(coffee, recipe) + offset(grinder)

with fineness on one common scale, microns of burr gap. For a grinder whose
unit is known in microns the scale is fixed and only the offset (where its
zero really is) is fitted. For one read off an unmarked dial both are fitted,
which needs at least three coffees in common with others. Medians are used
throughout, so one odd entry cannot move a result, and a coffee's figures are
only published once enough different contributors agree to be worth showing.

Only records that pass tools/verify_record.py are used.
"""
import argparse
import base64
import glob
import hashlib
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_record as vr  # noqa: E402

MIN_ITEMS_FOR_SCALE = 3     # coffees in common before an unmarked dial's scale is fitted
# Bean age. As roasted coffee ages a shot runs faster at the same grind, so its owner grinds
# finer. The rate is measured, not assumed: from contributors who settled the same coffee on
# the same grinder at two ages at least this many days apart.
MIN_AGE_GAP_DAYS = 5
MIN_AGE_PAIRS = 3           # such pairs before a rate is published at all
MAX_AGE_DAYS = 365
ROUNDS = 60


def library_file(library_id):
    """'portrait/idjwi-island' -> 'portrait__idjwi-island', as the firmware does."""
    if not library_id or any(not (c.islower() or c.isdigit() or c in "-/") for c in library_id):
        return None
    return library_id.replace("/", "__")


def recipe_class(recipe):
    """Recipes close enough for one grind: dose to half a gram, yield to two grams."""
    return round(recipe["dose_g"] * 2) / 2, round(recipe["yield_g"] / 2) * 2


def age_days(body):
    """Days off roast when the record was made, or None."""
    import datetime
    try:
        roast = datetime.date.fromisoformat(body["roast_date"])
        made = datetime.date.fromisoformat(body["at"][:10])
    except (KeyError, ValueError, TypeError):
        return None
    days = (made - roast).days
    return days if 0 <= days <= MAX_AGE_DAYS else None


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_observations(root, accept_unsigned=False, log=print):
    """Returns a list of dicts, one per accepted dial-in."""
    keys = vr.load_keys(os.path.join(root, "keys"))
    published = {}   # (kid, local id) -> library id
    for path in glob.glob(os.path.join(root, "status", "*.json")):
        kid = os.path.splitext(os.path.basename(path))[0]
        try:
            for entry in read_json(path).get("coffees", []):
                if entry.get("state") == "published" and entry.get("library_id"):
                    published[(kid, entry.get("local_id"))] = entry["library_id"]
        except (ValueError, OSError, AttributeError):
            log(f"status file ignored: {path}")
    observations = []
    for path in sorted(glob.glob(os.path.join(root, "dialins", "**", "*.json"), recursive=True)):
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
            try:
                kind, kid, body = vr.verify(text, keys)
            except vr.Refused as error:
                envelope = json.loads(text)
                if not (accept_unsigned and envelope.get("alg") == "EMULATOR-UNSIGNED"):
                    raise
                body = json.loads(envelope["body"])     # for trying the flow with the emulator only
                kind, kid = vr.check_body(body), envelope["kid"]
                del error
            if kind != "dialin":
                continue
        except (vr.Refused, ValueError, KeyError, OSError) as error:
            log(f"skipped {path}: {error}")
            continue
        coffee = body["coffee"]
        library_id = coffee.get("library_id") or published.get((kid, coffee.get("local_id")))
        if not library_file(library_id):
            continue    # a coffee that is not published: nothing to file it under
        grinder = body["grinder"]
        observations.append({
            "kid": kid,
            "instance": (kid, grinder["calibration"]),
            "unit": grinder["unit"],
            "um_per_unit": grinder.get("um_per_unit", 0) or 0,
            "model_id": grinder.get("model_id", 0) or 0,
            # The same model, for comparing owners of one: the library's entry if it has
            # one, else the firmware's own number for it.
            "model_key": grinder.get("library_id") or (grinder.get("model_id", 0) or 0),
            "item": (library_id, recipe_class(body["recipe"])),
            "setting": float(body["grind"]),
            "time_s": float(body["result"]["time_s"]),
            "age_days": age_days(body),
        })
    return observations


def collapse(observations):
    """One figure per grinder and item: the median of what that grinder reported."""
    groups = {}
    for o in observations:
        groups.setdefault((o["instance"], o["item"]), []).append(o)
    points = []
    for (instance, item), group in groups.items():
        ages = [o["age_days"] for o in group if o.get("age_days") is not None]
        points.append(dict(group[0], setting=statistics.median(o["setting"] for o in group),
                           time_s=statistics.median(o["time_s"] for o in group), count=len(group),
                           age_days=statistics.median(ages) if ages else None))
    return points


def fit(points):
    """Returns (fineness {item: um}, scale {instance: a}, offset {instance: b})."""
    by_instance, by_item = {}, {}
    for p in points:
        by_instance.setdefault(p["instance"], []).append(p)
        by_item.setdefault(p["item"], []).append(p)
    scale = {g: 1.0 / ps[0]["um_per_unit"] for g, ps in by_instance.items() if ps[0]["um_per_unit"] > 0}
    known = set(scale)
    offset = {g: 0.0 for g in known}
    fineness = {}
    for item, ps in by_item.items():
        values = [p["setting"] / scale[p["instance"]] for p in ps if p["instance"] in known]
        if values:
            fineness[item] = statistics.median(values)
    for _ in range(ROUNDS):
        before = dict(fineness)
        for g in known:
            residuals = [p["setting"] - scale[g] * fineness[p["item"]]
                         for p in by_instance[g] if p["item"] in fineness]
            if residuals:
                offset[g] = statistics.median(residuals)
        for g, ps in by_instance.items():
            if g in known:
                continue
            xy = [(fineness[p["item"]], p["setting"]) for p in ps if p["item"] in fineness]
            scale.pop(g, None)
            offset.pop(g, None)
            if len(xy) < MIN_ITEMS_FOR_SCALE:
                continue
            mx = sum(x for x, _ in xy) / len(xy)
            my = sum(y for _, y in xy) / len(xy)
            var = sum((x - mx) ** 2 for x, _ in xy)
            if var <= 0:
                continue
            a = sum((x - mx) * (y - my) for x, y in xy) / var
            if a <= 0:       # coarser must be a bigger number on the common scale too
                continue
            scale[g], offset[g] = a, my - a * mx
        for item, ps in by_item.items():
            values = [(p["setting"] - offset[p["instance"]]) / scale[p["instance"]]
                      for p in ps if p["instance"] in scale]
            if values:
                fineness[item] = statistics.median(values)
        # The whole scale could slide by a constant with every offset sliding
        # the other way. Pin it: the marked grinders' offsets centre on zero.
        marked = [offset[g] / scale[g] for g in known]
        if marked:
            slide = statistics.median(marked)
            for g in scale:
                offset[g] -= scale[g] * slide
            for item in fineness:
                fineness[item] += slide
        if all(abs(fineness[i] - before.get(i, 1e9)) < 1e-6 for i in fineness):
            break
    return fineness, scale, offset


def age_rate(observations, scale):
    """Microns of burr gap per day off roast, and how many pairs it rests on.

    A pair is the same grinder (same calibration) settling the same coffee and recipe
    at two ages. Whatever the grinder's offset and the coffee's fineness are, they are
    the same in both, so the difference is the ageing alone. The median over all
    pairs is the rate; None until there are enough.
    """
    groups = {}
    for o in observations:
        if o.get("age_days") is not None and o["instance"] in scale:
            groups.setdefault((o["instance"], o["item"]), []).append(o)
    rates = []
    for (instance, _), group in groups.items():
        group.sort(key=lambda o: o["age_days"])
        for i, young in enumerate(group):
            for old in group[i + 1:]:
                gap = old["age_days"] - young["age_days"]
                if gap >= MIN_AGE_GAP_DAYS:
                    rates.append((old["setting"] - young["setting"]) / scale[instance] / gap)
    if len(rates) < MIN_AGE_PAIRS:
        return None, len(rates)
    rate = statistics.median(rates)
    return (rate if -5.0 <= rate <= 5.0 else None), len(rates)


def fit_with_age(observations):
    """The fit, allowing for age. Returns (points, fineness, scale, offset, rate, pairs).

    A first fit gives every grinder's scale, which is what turns its settings into
    microns; with those the ageing rate is measured. If there is one, each dial-in
    is moved to the age its coffee was typically settled at, so that one made on an
    old bag neither widens the spread nor drags the coffee's figure, and the fit is
    done again. Each point's age_days is then the age its coffee's figure is for.
    """
    points = collapse(observations)
    fineness, scale, offset = fit(points)
    rate, pairs = age_rate(observations, scale)
    if rate is None:
        return points, fineness, scale, offset, rate, pairs
    by_item = {}
    for o in observations:
        if o.get("age_days") is not None:
            by_item.setdefault(o["item"], []).append(o["age_days"])
    usual = {item: statistics.median(ages) for item, ages in by_item.items()}
    moved = []
    for o in observations:
        o = dict(o)
        if o.get("age_days") is not None and o["instance"] in scale:
            o["setting"] -= scale[o["instance"]] * rate * (o["age_days"] - usual[o["item"]])
            o["age_days"] = usual[o["item"]]
        moved.append(o)
    points = collapse(moved)
    fineness, scale, offset = fit(points)
    return points, fineness, scale, offset, rate, pairs


def build(root, accept_unsigned=False, min_contributors=2, log=print):
    observations = load_observations(root, accept_unsigned, log)
    points, fineness, scale, offset, rate, pairs = fit_with_age(observations)
    by_item, by_instance = {}, {}
    for p in points:
        by_item.setdefault(p["item"], []).append(p)
        by_instance.setdefault(p["instance"], []).append(p)
    out = os.path.join(root, "index")
    os.makedirs(os.path.join(out, "dialin"), exist_ok=True)
    os.makedirs(os.path.join(out, "fit"), exist_ok=True)

    def write(path, value):
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(value, f, separators=(",", ":"), sort_keys=True)

    # Published coffees.
    coffees = []
    for path in sorted(glob.glob(os.path.join(root, "catalog", "**", "*.json"), recursive=True)):
        try:
            entry = read_json(path)
            vr.check_coffee(entry, full=False)
            if not library_file(entry.get("id")):
                raise vr.Refused("id is not of the form roaster/name in lower case")
            coffees.append(entry)
        except (vr.Refused, ValueError, OSError) as error:
            log(f"catalog entry ignored: {path}: {error}")
    write(os.path.join(out, "coffees.json"), {"v": 1, "coffees": coffees})

    # How fast the grind follows the coffee's age.
    aging = {"v": 1, "pairs": pairs}
    if rate is not None:
        aging["um_per_day"] = round(rate, 3)
    write(os.path.join(out, "age.json"), aging)

    # Grinder models reviewers have listed.
    listed = []
    for path in sorted(glob.glob(os.path.join(root, "grinders", "*.json"))):
        try:
            entry = read_json(path)
            vr._text(entry, "model", 31)
            vr._text(entry, "unit", 7)
            vr._text(entry, "burrs", 23, required=False)
            vr._number(entry, "um_per_unit", 0.01, 1000, required=False)
            if not library_file(entry.get("id")) or "/" in entry["id"]:
                raise vr.Refused("id is not a plain lower-case name")
            listed.append({k: entry[k] for k in ("id", "model", "burrs", "unit", "um_per_unit") if k in entry})
        except (vr.Refused, ValueError, OSError, AttributeError, TypeError) as error:
            log(f"grinder entry ignored: {path}: {error}")
    write(os.path.join(out, "grinders.json"), {"v": 1, "grinders": listed})

    # What was settled on, per coffee.
    per_coffee = {}
    for item, ps in by_item.items():
        if item not in fineness:
            continue
        contributors = {p["kid"] for p in ps}
        if len(contributors) < min_contributors:
            continue
        residuals = [abs((p["setting"] - offset[p["instance"]]) / scale[p["instance"]] - fineness[item])
                     for p in ps if p["instance"] in scale]
        models = {}
        for p in ps:
            if p.get("model_key"):
                models.setdefault((p["model_key"], p["unit"]), {})[p["kid"]] = p["setting"]
        library_id, (dose, yield_g) = item
        per_coffee.setdefault(library_id, []).append({
            "dose_g": dose, "yield_g": yield_g,
            "contributors": len(contributors),
            "dialins": sum(p["count"] for p in ps),
            "time_s": round(statistics.median(p["time_s"] for p in ps), 1),
            **({"age_days": round(statistics.median(a))} if (a := [p["age_days"] for p in ps
                                                            if p.get("age_days") is not None]) else {}),
            "fineness_um": round(fineness[item], 1),
            "spread_um": round(1.4826 * statistics.median(residuals), 1) if len(residuals) > 1 else 0,
            "models": [dict({"library_id": m} if isinstance(m, str) else {"model_id": m}, unit=u,
                            median=round(statistics.median(v.values()), 1), n=len(v))
                       for (m, u), v in sorted(models.items(), key=lambda kv: (str(kv[0][0]), kv[0][1]))],
        })
    for library_id, recipes in per_coffee.items():
        write(os.path.join(out, "dialin", library_file(library_id) + ".json"),
              {"v": 1, "coffee": library_id, "recipes": sorted(recipes, key=lambda r: (r["dose_g"], r["yield_g"]))})

    # How each contributor's grinder sits against the scale.
    per_kid = {}
    for g, ps in by_instance.items():
        if g not in scale:
            continue
        common = sum(1 for p in ps if len({q["kid"] for q in by_item[p["item"]]}) > 1)
        if common == 0:
            continue     # nothing shared with anyone: its offset is its own guess
        per_kid.setdefault(g[0], []).append({
            "calibration": g[1], "scale": round(scale[g], 5), "offset": round(offset[g], 2),
            "coffees_in_common": common})
    for kid, grinders in per_kid.items():
        write(os.path.join(out, "fit", kid + ".json"),
              {"v": 1, "grinders": sorted(grinders, key=lambda x: x["calibration"])})
    log(f"{len(observations)} dial-ins used, {len(coffees)} coffees listed, "
        f"{len(per_coffee)} with community figures, {len(per_kid)} contributors fitted")
    return fineness, scale, offset


# ---- example data and self-test -------------------------------------------------
EXAMPLE_COFFEES = [
    {"id": "portrait/idjwi-island", "name": "Idjwi Island", "roaster": "Portrait", "origin": "DR Congo",
     "process": "washed", "roast_level": "medium-light"},
    {"id": "example/ethiopia-guji", "name": "Ethiopia Guji", "roaster": "Example Roasters",
     "origin": "Ethiopia", "region": "Guji", "process": "natural", "roast_level": "light"},
    {"id": "example/colombia-decaf", "name": "Colombia Decaf", "roaster": "Example Roasters",
     "origin": "Colombia", "process": "sugarcane decaf", "roast_level": "medium"},
    {"id": "example/kenya-aa", "name": "Kenya AA", "roaster": "Example Roasters", "origin": "Kenya",
     "process": "washed", "roast_level": "light"},
]
# The invented truth the example is made from: fineness in microns per coffee.
EXAMPLE_FINENESS = {"portrait/idjwi-island": 250.0, "example/ethiopia-guji": 236.0,
                    "example/colombia-decaf": 266.0, "example/kenya-aa": 228.0}
# name: (private key, grinder, true scale, true offset, coffees dialled)
EXAMPLE_PEOPLE = {
    "anna": (0x1111, {"model_id": 1, "model": "Mahlkonig E64 WS", "unit": "um", "um_per_unit": 1}, 1.0, 6.0,
             ["portrait/idjwi-island", "example/ethiopia-guji", "example/colombia-decaf", "example/kenya-aa"]),
    "ben": (0x2222, {"model_id": 1, "model": "Mahlkonig E64 WS", "unit": "um", "um_per_unit": 1}, 1.0, -8.0,
            ["portrait/idjwi-island", "example/ethiopia-guji", "example/kenya-aa"]),
    "cara": (0x3333, {"model_id": 2, "model": "LUCCA Atom 75", "unit": "steps", "um_per_unit": 5}, 0.2, 2.0,
             ["portrait/idjwi-island", "example/ethiopia-guji", "example/colombia-decaf", "example/kenya-aa"]),
    "dev": (0x4444, {"model_id": 3, "model": "DF64", "unit": "dial"}, 0.25, 10.0,
            ["portrait/idjwi-island", "example/ethiopia-guji", "example/colombia-decaf", "example/kenya-aa"]),
}


# Invented: how fast the example's contributors went finer as a bag aged, and who
# settled which coffee a second time.
EXAMPLE_UM_PER_DAY = -0.8
EXAMPLE_AGED = {"anna": ["portrait/idjwi-island", "example/kenya-aa"], "ben": ["example/ethiopia-guji"],
                "cara": ["example/colombia-decaf"]}


def _sign(private, body_text):
    e = int.from_bytes(hashlib.sha256(body_text.encode()).digest(), "big")
    k = int.from_bytes(hashlib.sha256(private.to_bytes(32, "big") + body_text.encode()).digest(), "big") % vr.N
    r = vr._mul(k, vr.G)[0] % vr.N
    s = pow(k, -1, vr.N) * (e + r * private) % vr.N
    return base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()


def _envelope(private, kid, body):
    text = json.dumps(body, separators=(",", ":"))
    return json.dumps({"v": 1, "kid": kid, "alg": "ES256", "sig": _sign(private, text), "body": text},
                      separators=(",", ":"))


def make_example(root, log=print):
    """Four invented contributors with real signatures (throwaway keys), four coffees."""
    def put(path, text):
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    for coffee in EXAMPLE_COFFEES:
        put(os.path.join("catalog", coffee["id"] + ".json"), json.dumps(coffee, indent=1))
    truth = {}
    for name, (private, grinder, a, b, coffees) in EXAMPLE_PEOPLE.items():
        point = vr._mul(private, vr.G)
        raw = b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        kid = vr.key_id(raw)
        put(f"keys/{kid}.json", _envelope(private, kid, {
            "t": "key", "v": 1, "alg": "ES256", "key": base64.b64encode(raw).decode()}))
        status = []
        for n, library_id in enumerate(coffees, start=1):
            setting = round(a * EXAMPLE_FINENESS[library_id] + b)
            truth[(kid, library_id)] = setting
            entry = next(c for c in EXAMPLE_COFFEES if c["id"] == library_id)
            put(f"dialins/2026/10/{kid}-{n}.json", _envelope(private, kid, {
                "t": "dialin", "v": 1, "at": "2026-10-01T08:00:00Z", "roast_date": "2026-09-21",
                "coffee": {"local_id": n, "name": entry["name"]},
                "recipe": {"dose_g": 18, "yield_g": 36, "target_time_s": 26},
                "grinder": dict(grinder, calibration=0),
                "grind": setting,
                "result": {"time_s": 26.0 + 0.2 * n, "basis": "total", "shots": 3}}))
            status.append({"local_id": n, "record": n, "state": "published", "library_id": library_id})
            if name in EXAMPLE_AGED and library_id in EXAMPLE_AGED[name]:
                # The same bag three weeks on: settled again, finer.
                later = round(a * (EXAMPLE_FINENESS[library_id] + EXAMPLE_UM_PER_DAY * 21) + b)
                put(f"dialins/2026/10/{kid}-{n}b.json", _envelope(private, kid, {
                    "t": "dialin", "v": 1, "at": "2026-10-22T08:00:00Z", "roast_date": "2026-09-21",
                    "coffee": {"local_id": n, "name": entry["name"]},
                    "recipe": {"dose_g": 18, "yield_g": 36, "target_time_s": 26},
                    "grinder": dict(grinder, calibration=0),
                    "grind": later,
                    "result": {"time_s": 26.1, "basis": "total", "shots": 3}}))
        put(f"status/{kid}.json", json.dumps({"v": 1, "coffees": status}))
    log(f"example library written to {root}")
    return truth


def self_test():
    import tempfile
    # 1. The fit recovers invented scales and offsets from exact data, and
    #    predicts a setting nobody reported.
    people = {"a": (1.0, 5.0, True), "b": (1.0, -8.0, True), "c": (0.2, 3.0, True), "d": (0.25, 10.0, False)}
    truth = {"k1": 250.0, "k2": 236.0, "k3": 266.0, "k4": 228.0, "k5": 242.0}
    points = []
    for who, (a, b, marked) in people.items():
        for coffee, f in truth.items():
            if (who, coffee) in (("b", "k5"), ("d", "k4")):
                continue    # held back
            points.append({"kid": who, "instance": (who, 0), "unit": "u", "model_id": 0, "model_key": 0,
                           "um_per_unit": 1 / a if marked else 0, "item": (coffee, (18.0, 36)),
                           "setting": a * f + b, "time_s": 26.0, "count": 1})
    fineness, scale, offset = fit(points)
    for who, (a, b, _) in people.items():
        assert abs(scale[(who, 0)] - a) < 1e-6, (who, scale)
    for who, coffee in (("b", "k5"), ("d", "k4"), ("a", "k1")):
        a, b, _ = people[who]
        predicted = scale[(who, 0)] * fineness[(coffee, (18.0, 36))] + offset[(who, 0)]
        assert abs(predicted - (a * truth[coffee] + b)) < 1e-6, (who, coffee, predicted)
    # One wild entry among three does not move the coffee.
    wild = [dict(p) for p in points]
    for p in wild:
        if p["kid"] == "a" and p["item"][0] == "k2":
            p["setting"] += 60
    f2, _, _ = fit(wild)
    assert abs(f2[("k2", (18.0, 36))] - fineness[("k2", (18.0, 36))]) < 1.5
    # An unmarked dial with only two coffees is left out, not guessed.
    few = [p for p in points if not (p["kid"] == "d" and p["item"][0] not in ("k1", "k2"))]
    _, s3, _ = fit(few)
    assert ("d", 0) not in s3

    # 1b. The ageing rate: exact from invented pairs, withheld when there are too few,
    #     and unmoved by one contributor who went the other way.
    def aged(who, coffee, age, setting):
        return {"instance": (who, 0), "item": (coffee, (18.0, 36)), "age_days": age, "setting": setting}
    marks = {("a", 0): 1.0, ("c", 0): 0.2}
    obs = [aged("a", "k1", 8, 250), aged("a", "k1", 28, 234), aged("a", "k2", 10, 240), aged("a", "k2", 20, 232),
           aged("c", "k1", 5, 52), aged("c", "k1", 30, 48)]
    rate, pairs = age_rate(obs, marks)
    assert pairs == 3 and abs(rate - (-0.8)) < 1e-9, (rate, pairs)
    assert age_rate(obs[:4], marks) == (None, 2)                       # too few to say
    assert age_rate(obs + [aged("a", "k1", 9, 250)], marks)[1] == 4   # 8 and 9 days: too close to count
    odd = obs + [aged("c", "k2", 5, 40), aged("c", "k2", 25, 60)]    # one bag that went coarser
    assert abs(age_rate(odd, marks)[0] - (-0.8)) < 1e-9
    assert age_rate([dict(o, age_days=None) for o in obs], marks) == (None, 0)

    # 2. End to end: signed example records in, index files out.
    with tempfile.TemporaryDirectory() as root:
        true_settings = make_example(root, log=lambda *_: None)
        build(root, log=lambda *_: None)
        index = read_json(os.path.join(root, "index", "coffees.json"))
        assert len(index["coffees"]) == 4
        guji = read_json(os.path.join(root, "index", "dialin", "example__ethiopia-guji.json"))
        entry = guji["recipes"][0]
        assert entry["contributors"] == 4 and entry["dose_g"] == 18 and entry["yield_g"] == 36
        assert 10 <= entry["age_days"] <= 31, entry
        aging = read_json(os.path.join(root, "index", "age.json"))
        assert aging["pairs"] == 4 and abs(aging["um_per_day"] - EXAMPLE_UM_PER_DAY) < 0.15, aging
        assert entry["spread_um"] < 4, entry       # settings are whole numbers: a little rounding
        e64 = [m for m in entry["models"] if m["model_id"] == 1][0]
        assert e64["n"] == 2 and e64["unit"] == "um"
        # Ben never dialled the decaf. His fit and the decaf's fineness give his setting.
        decaf = read_json(os.path.join(root, "index", "dialin", "example__colombia-decaf.json"))["recipes"][0]
        ben = [k for k in os.listdir(os.path.join(root, "index", "fit"))]
        fits = {k[:-5]: read_json(os.path.join(root, "index", "fit", k))["grinders"][0] for k in ben}
        ben_kid = vr.key_id(b"\x04" + b"".join(c.to_bytes(32, "big") for c in vr._mul(0x2222, vr.G)))
        predicted = fits[ben_kid]["scale"] * decaf["fineness_um"] + fits[ben_kid]["offset"]
        assert abs(predicted - (266.0 - 8.0)) < 3, predicted
        assert fits[ben_kid]["coffees_in_common"] == 3
        # A record that fails verification is left out.
        victim = glob.glob(os.path.join(root, "dialins", "2026", "10", "*.json"))[0]
        with open(victim, encoding="utf-8") as f:
            text = f.read()
        with open(victim, "w", encoding="utf-8") as f:
            f.write(text.replace('\\"grind\\":', '\\"grind\\":1'))
        skipped = []
        build(root, log=skipped.append)
        assert any("signature does not match" in line or "outside" in line for line in skipped), skipped
        del true_settings
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--root", help="the library's folder")
    parser.add_argument("--min-contributors", type=int, default=2,
                        help="different contributors needed before a coffee's figures are published")
    parser.add_argument("--accept-unsigned", action="store_true",
                        help="also use records written by the PC emulator. For trying the flow only: "
                             "never on the real library")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--make-example", metavar="FOLDER",
                        help="write an invented library (four contributors, four coffees) to FOLDER")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.make_example:
        make_example(args.make_example)
    elif args.root:
        build(args.root, args.accept_unsigned, args.min_contributors)
    else:
        parser.error("give --root, --make-example or --self-test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
