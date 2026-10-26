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
    taste.json                          coffee ratings: each coffee's taste (from 2 contributors),
                                        and anonymous drinkers' stars, for recommendations; per
                                        subscription service, the taste of the coffees it sent
    services.json                       listed subscription services, with their reviews (from 2
                                        contributors)
    dialin/<coffee file>.json           what contributors settled on for one coffee
    fit/<key id>.json                   how each contributor's grinder sits against the common scale

The fit (docs/COMMUNITY.md, section 6). Every dial-in says: on this grinder,
this coffee with this recipe settled at this setting. Settings on different
grinders do not compare directly, so the model is

    setting = scale(grinder) x fineness(coffee, recipe) + offset(grinder)

with fineness on one common axis. The scale belongs to a grinder MODEL and is
learned from all its owners together; only the offset (where one grinder's zero
sits) belongs to one grinder. So a new owner of a known model needs one coffee in
common with anyone, and a grinder that is zeroed again keeps its scale.

Where a model's microns per unit is known (the maker's, or a reviewed entry) its
scale is fixed and the axis is microns of burr gap. Grinders are linked by the
coffees they share; a group of linked grinders with none marked in microns is fitted
too, on a relative axis in the unit of its best-covered model, with its own id
("axis"). Fineness from different axes is never mixed. A coffee that no fit can place
still gets its same-model medians. Medians are used throughout, so one odd entry
cannot move a result, and a coffee's figures are only published once enough different
contributors agree to be worth showing.

Only records that pass tools/verify_record.py are used.
"""
import argparse
import base64
import glob
import hashlib
import hmac
import json
import math
import os
import statistics
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_record as vr  # noqa: E402

INDEX_WARN_BYTES = 57344  # 56 kB: controllers read an index file into 64 kB (LIBRARY_TEXT_SIZE)

MIN_ITEMS_FOR_SCALE = 3     # coffees in common before an unmarked dial's scale is fitted
# Bean age. As roasted coffee ages a shot runs faster at the same grind, so its owner grinds
# finer. The rate is measured, not assumed: from contributors who settled the same coffee on
# the same grinder at two ages at least this many days apart.
MIN_AGE_GAP_DAYS = 5
MIN_AGE_PAIRS = 3           # such pairs before a rate is published at all
MAX_AGE_DAYS = 365
# How much of a day in the freezer still counts as a day of ageing. Not measured; keep equal to
# FROZEN_AGING_FRACTION in src/core/Community.h.
FROZEN_AGING_FRACTION = 0.10
ROUNDS = 60
# Flow. Dial-ins are made at different brew speeds: one owner aims at 24 s, another at 32 s.
# How far the grind has to move for a given change of flow is the sensitivity KAPPA, in axis
# units per unit of ln(flow). It is measured from the library's own dial-ins when there are
# enough, else on the microns axis a prior is used: the advisor's starting guess of 3 um per
# second, at about 28 s (the same figure the controller steers by before it has learned its own).
KAPPA_PRIOR_UM = 84.0
KAPPA_MIN_POINTS = 8        # within-coffee pairs before a measured figure is believed
KAPPA_MIN_SPREAD = 0.03     # spread of ln(flow) needed for a slope to mean anything
KAPPA_PRIOR_BAND = 4.0      # a microns figure outside prior/4 .. prior x 4 is noise


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
    # Days the bag spent in the freezer are not days of ageing (controllers send them as frozen_days).
    frozen = body.get("frozen_days")
    if isinstance(frozen, (int, float)) and not isinstance(frozen, bool) and frozen > 0:
        days -= int(round(min(frozen, days) * (1.0 - FROZEN_AGING_FRACTION)))
    return days if 0 <= days <= MAX_AGE_DAYS else None


def unit_key(grinder):
    """A grinder's unit as the index groups it: a dial read in tenths and one read in whole steps
    are not the same unit even if both are called 'dial'. Keep equal to grinderUnitKey in
    src/core/SettingFormat.h."""
    unit = grinder["unit"]
    if grinder.get("sub_steps", 0) >= 2:
        return f"{unit}/r{grinder['sub_steps']}"
    if grinder.get("divisor", 1) > 1:
        return f"{unit}/d{grinder['divisor']}"
    return unit


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def model_numbers(root):
    """The firmware's model numbers mapped to their entries in the library's list of grinders (each
    built-in is seeded as an entry with its model_id), so a dial-in that names its grinder only by
    number pools with those that name the entry: one model, one key."""
    numbers = {}
    for path in glob.glob(os.path.join(root, "grinders", "*.json")):
        try:
            entry = read_json(path)
            if isinstance(entry.get("model_id"), int) and entry["model_id"] > 0 and library_file(entry.get("id")):
                numbers[entry["model_id"]] = entry["id"]
        except (ValueError, OSError, AttributeError):
            pass
    return numbers


def load_observations(root, accept_unsigned=False, log=print):
    """Returns a list of dicts, one per accepted dial-in."""
    keys = vr.load_keys(os.path.join(root, "keys"))
    numbers = model_numbers(root)
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
            "unit": unit_key(grinder),
            "um_per_unit": grinder.get("um_per_unit", 0) or 0,
            "model_id": grinder.get("model_id", 0) or 0,
            # The same model, for comparing owners of one: the library's entry if it has
            # one (named in the record, or the entry the firmware's number is listed as), else the
            # firmware's own number for it.
            "model_key": (grinder.get("library_id") or numbers.get(grinder.get("model_id", 0) or 0)
                          or (grinder.get("model_id", 0) or 0)),
            "item": (library_id, recipe_class(body["recipe"])),
            "setting": float(body["grind"]),
            "time_s": float(body["result"]["time_s"]),
            "basis": body["result"].get("basis", "total"),
            # grams per second over the time the owner steers by: yield over that time
            "flow_gs": (float(body["recipe"]["yield_g"]) / float(body["result"]["time_s"])
                        if float(body["result"]["time_s"]) > 0 and float(body["recipe"]["yield_g"]) > 0 else None),
            "age_days": age_days(body),
        })
    return observations


KEY_PART = 24   # the controller's COFFEE_KEY_PART (src/net/Web.cpp tasteKey): 23 characters a part


def key_part(text):
    """Lower case, runs of spaces as one, none at the ends, at most 23 characters: exactly as the
    controller's tasteKey squeezes a roaster or a name, so the two keys match."""
    out, space = [], False
    for c in str(text or ""):
        if len(out) + 1 >= KEY_PART:
            break
        if c.isspace():
            space = len(out) > 0
            continue
        if space and len(out) + 2 < KEY_PART:
            out.append(" ")
        space = False
        out.append(c.lower() if c.isascii() else c)
    return "".join(out)


def taste_key(coffee, kid, published):
    """The coffee a rating is about: its library entry, else its roaster and name."""
    library_id = coffee.get("library_id") or published.get((kid, coffee.get("local_id")))
    if library_file(library_id):
        return library_id
    roaster = key_part(coffee.get("roaster", ""))
    name = key_part(coffee.get("name", ""))
    return f"~{roaster}/{name}" if name else None


def build_taste(root, min_contributors=2, log=print):
    """index/taste.json: per coffee rated by enough contributors, its mean taste; and, per anonymous
    drinker with three or more of those coffees rated, their stars (for 'people like you')."""
    keys = vr.load_keys(os.path.join(root, "keys"))
    published = {}
    for path in glob.glob(os.path.join(root, "status", "*.json")):
        kid = os.path.splitext(os.path.basename(path))[0]
        try:
            for entry in read_json(path).get("coffees", []):
                if entry.get("state") == "published" and entry.get("library_id"):
                    published[(kid, entry.get("local_id"))] = entry["library_id"]
        except (ValueError, OSError, AttributeError):
            pass
    ratings = []
    for path in sorted(glob.glob(os.path.join(root, "tastes", "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                kind, kid, body = vr.verify(f.read(), keys)
            if kind != "taste" or body.get("withdrawn"):
                continue    # a withdrawn rating counts for nothing
        except (vr.Refused, ValueError, KeyError, OSError) as error:
            log(f"skipped {path}: {error}")
            continue
        key = taste_key(body["coffee"], kid, published)
        if key:
            ratings.append((key, kid, int(body.get("drinker", 0)), body))
    listed_services = set(os.path.splitext(os.path.basename(p))[0]
                          for p in glob.glob(os.path.join(root, "services", "*.json")))
    by_coffee = {}
    for key, kid, drinker, body in ratings:
        by_coffee.setdefault(key, []).append((kid, drinker, body))
    coffees = {}
    for key, rs in sorted(by_coffee.items()):
        if len({kid for kid, _, _ in rs}) < min_contributors:
            continue    # too few people: nothing published about it
        stars = [int(b["stars"]) for _, _, b in rs]
        cup = {}
        for name in vr.CUP:
            values = [b["cup"][name] for _, _, b in rs if name in b.get("cup", {})]
            if len(values) >= 2:
                cup[name] = round(statistics.fmean(values), 2)
        tasted = [b.get("flavours", []) for _, _, b in rs if b.get("flavours")]
        flavours = ({name: round(sum(name in f for f in tasted) / len(tasted), 2) for name in vr.FLAVOURS}
                    if len(tasted) >= 2 else {})
        first = rs[0][2]["coffee"]
        coffees[key] = {"name": first.get("name", ""), "roaster": first.get("roaster", ""),
                        "n": len(rs), "contributors": len({kid for kid, _, _ in rs}),
                        "stars": round(statistics.fmean(stars), 2),
                        "stars_hist": [stars.count(n) for n in range(1, 6)],
                        "cup": cup, "flavours": flavours}
    # Per listed subscription service: how the coffees it sent tasted, once enough people rated them.
    by_service = {}
    for key, kid, drinker, body in ratings:
        if body.get("service") in listed_services:
            by_service.setdefault(body["service"], []).append((kid, drinker, body))
    services = {}
    for sid, rs in sorted(by_service.items()):
        if len({kid for kid, _, _ in rs}) < min_contributors:
            continue
        stars = [int(b["stars"]) for _, _, b in rs]
        cup = {}
        for name in vr.CUP:
            values = [b["cup"][name] for _, _, b in rs if name in b.get("cup", {})]
            if len(values) >= 2:
                cup[name] = round(statistics.fmean(values), 2)
        tasted = [b.get("flavours", []) for _, _, b in rs if b.get("flavours")]
        flavours = ({name: round(sum(name in f for f in tasted) / len(tasted), 2) for name in vr.FLAVOURS}
                    if len(tasted) >= 2 else {})
        services[sid] = {"n": len(rs), "contributors": len({kid for kid, _, _ in rs}),
                         "stars": round(statistics.fmean(stars), 2), "cup": cup, "flavours": flavours}
    # Who is who stays in the library: a keyed hash, the key from the build's secrets (BBW_PEOPLE_SALT).
    # Without it a fixed key, so the file does not change at every build; the ids are then traceable.
    salt = os.environ.get("BBW_PEOPLE_SALT", "").encode()
    if not salt:
        salt = b"bbw-people-unsalted"
        if ratings:
            log("warning: BBW_PEOPLE_SALT is not set: drinker ids in index/taste.json can be traced to keys")

    def person_of(kid, drinker):
        return hmac.new(salt, f"{kid}/{drinker}".encode(), hashlib.sha256).hexdigest()[:12]

    people = {}
    for key, kid, drinker, body in ratings:
        if key in coffees:
            person = person_of(kid, drinker)
            people.setdefault(person, {})[key] = int(body["stars"])
    # A drinker's liking for a service: the mean of their stars for the coffees it sent ("svc:<id>").
    liking = {}
    for key, kid, drinker, body in ratings:
        sid = body.get("service")
        if sid in services:
            person = person_of(kid, drinker)
            liking.setdefault((person, sid), []).append(int(body["stars"]))
    for (person, sid), stars in liking.items():
        if person in people:
            people[person]["svc:" + sid] = round(statistics.fmean(stars))
    people = [{"id": p, "r": r} for p, r in sorted(people.items())
              if sum(not k.startswith("svc:") for k in r) >= 3]
    return {"v": 1, "coffees": coffees, "people": people, "services": services}


def build_services(root, min_contributors=2, log=print):
    """index/services.json: the subscription services reviewers have listed, each with what people who
    use it think of it, once at least `min_contributors` controllers have reviewed it."""
    keys = vr.load_keys(os.path.join(root, "keys"))
    listed = []
    for path in sorted(glob.glob(os.path.join(root, "services", "*.json"))):
        try:
            entry = read_json(path)
            vr.check_service(entry, full=False)
            sid = entry.get("id")
            if (not isinstance(sid, str) or not sid or len(sid) > 39 or sid != os.path.splitext(os.path.basename(path))[0]
                    or any(not (c.islower() or c.isdigit() or c == "-") for c in sid)):
                raise vr.Refused("id is not the file's plain lower-case name")
            listed.append({k: entry[k] for k in ("id",) + tuple(f for f in (
                "name", "url", "manage_url", "platform", "kind", "ships_to", "cadences", "price_from_cents",
                "currency", "style", "sourcing", "image", "icon", "color", "about")) if k in entry})
        except (vr.Refused, ValueError, OSError, AttributeError, TypeError, KeyError) as error:
            log(f"service entry ignored: {path}: {error}")
    ids = {s["id"] for s in listed}
    reviews = {}
    for path in sorted(glob.glob(os.path.join(root, "svcreviews", "*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                kind, kid, body = vr.verify(f.read(), keys)
            if kind != "service_review" or body["service"] not in ids:
                continue
        except (vr.Refused, ValueError, KeyError, OSError) as error:
            log(f"skipped {path}: {error}")
            continue
        reviews.setdefault(body["service"], []).append((kid, body))
    for service in listed:
        rs = reviews.get(service["id"], [])
        if len({kid for kid, _ in rs}) < min_contributors:
            continue    # too few people: nothing published about it
        stars = [int(b["stars"]) for _, b in rs]
        aspects = {}
        for name in vr.SERVICE_ASPECTS:
            values = [b["aspects"][name] for _, b in rs if name in b.get("aspects", {})]
            if len(values) >= 2:
                aspects[name] = round(statistics.fmean(values), 2)
        service["reviews"] = {"n": len(rs), "contributors": len({kid for kid, _ in rs}),
                              "stars": round(statistics.fmean(stars), 2),
                              "stars_hist": [stars.count(n) for n in range(1, 6)], "aspects": aspects}
    return {"v": 1, "services": listed}


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


def _group_of(p):
    """Grinders of one model, read in one unit, share a scale: same dial, same burrs. Only
    where each one's zero sits differs. A grinder nobody can say the model of is on its own."""
    if p.get("model_key"):
        return (p["model_key"], p["unit"])
    return ("own",) + tuple(p["instance"])


def zero_spread(values, minimum=3):
    """How far one model's owners sit from each other, in its own unit (robust, like the rest);
    None with fewer than `minimum`, where a spread would be a guess."""
    if len(values) < minimum:
        return None
    middle = statistics.median(values)
    return 1.4826 * statistics.median(abs(v - middle) for v in values)


def _fit_component(insts, by_instance, group_of, maker):
    """The fit for grinders that are linked through coffees they share.

    Returns (fineness {item: value}, scale {instance: a}, offset {instance: b}, axis, groups).
    `axis` says what fineness is measured in: 0 = microns of burr gap, which needs at least
    one grinder in the component whose maker's microns per unit is known; anything else
    is an arbitrary id for a relative axis, in the unit of the grinder that was used as the
    reference. Fineness from two different axes must never be put together.
    """
    members = {}
    for g in insts:
        members.setdefault(group_of[g], []).append(g)
    group_scale = {grp: a for grp, a in maker.items() if grp in members}
    if group_scale:
        axis = 0
        anchors = [g for g in insts if group_of[g] in group_scale]
    else:
        # No grinder here is marked in microns. Take the best-covered model as the
        # reference: its unit is the axis, its offsets are centred on zero.
        reference = max(members, key=lambda k: (len(members[k]),
                                                sum(len(by_instance[g]) for g in members[k]), str(k)))
        group_scale[reference] = 1.0
        anchors = list(members[reference])
        first = min(str(p["item"]) for g in insts for p in by_instance[g])
        axis = (zlib.crc32(first.encode()) & 0x7FFFFFFF) or 1
    fixed = set(group_scale)
    items = {}
    for g in insts:
        for p in by_instance[g]:
            items.setdefault(p["item"], []).append(p)
    offset = {g: 0.0 for g in insts if group_of[g] in group_scale}
    fineness = {}

    def refresh():
        for item, ps in items.items():
            values = [(p["setting"] - offset[p["instance"]]) / group_scale[group_of[p["instance"]]]
                      for p in ps if p["instance"] in offset]
            if values:
                fineness[item] = statistics.median(values)

    refresh()
    for _ in range(ROUNDS):
        before = dict(fineness)
        # 1. A model's scale, from every owner of it at once: each owner's settings against
        #    the coffees' fineness, with that owner's own zero taken out. An owner with one
        #    coffee adds nothing here, but is placed by it below.
        for grp, gs in members.items():
            if grp in fixed:
                continue
            sxy = sxx = 0.0
            points_n = owners = 0
            for g in gs:
                xy = [(fineness[p["item"]], p["setting"]) for p in by_instance[g] if p["item"] in fineness]
                if not xy:
                    continue
                mx = sum(x for x, _ in xy) / len(xy)
                my = sum(y for _, y in xy) / len(xy)
                sxx += sum((x - mx) ** 2 for x, _ in xy)
                sxy += sum((x - mx) * (y - my) for x, y in xy)
                points_n += len(xy)
                owners += 1
            slope = sxy / sxx if sxx > 0 else 0.0
            # Two degrees of freedom, as three coffees on one grinder used to give; the
            # slope must be positive: coarser is a bigger number on the common axis too.
            if points_n - owners >= MIN_ITEMS_FOR_SCALE - 1 and slope > 0:
                group_scale[grp] = slope
            else:
                group_scale.pop(grp, None)
        # 2. Each grinder's zero, now that its model's scale is known.
        offset.clear()
        for g in insts:
            grp = group_of[g]
            if grp not in group_scale:
                continue
            residuals = [p["setting"] - group_scale[grp] * fineness[p["item"]]
                         for p in by_instance[g] if p["item"] in fineness]
            if residuals:
                offset[g] = statistics.median(residuals)
        # 3. Each coffee's fineness, from every grinder that has a scale and a zero.
        refresh()
        # 4. The whole axis could slide by a constant with every offset sliding the other
        #    way. Pin it: the anchors' offsets centre on zero.
        marks = [offset[g] / group_scale[group_of[g]] for g in anchors if g in offset]
        if marks:
            slide = statistics.median(marks)
            for g in offset:
                offset[g] -= group_scale[group_of[g]] * slide
            for item in fineness:
                fineness[item] += slide
        if all(abs(fineness[i] - before.get(i, 1e9)) < 1e-6 for i in fineness):
            break
    scale = {g: group_scale[group_of[g]] for g in offset}
    groups = {}
    for grp in members:
        if grp not in group_scale:
            continue
        latest = {}
        for g in members[grp]:
            if g in offset and (g[0] not in latest or g[1] > latest[g[0]][1]):
                latest[g[0]] = g
        zeros = [offset[g] for g in latest.values()]
        groups[grp] = {"scale": group_scale[grp], "known": grp in maker, "instances": len(members[grp]),
                       "axis": axis, "offset_spread": zero_spread(zeros),
                       # where a grinder of this model typically sits: for a new owner who has no
                       # coffee in common with anyone yet. Not from one grinder alone.
                       "offset_zero": statistics.median(zeros) if len(zeros) >= 2 else None,
                       "offset_n": len(zeros)}
    return fineness, scale, offset, axis, groups


def fit_all(points):
    """Returns a dict: fineness {item: value}, scale and offset {instance: number}, axis_of
    {instance: axis}, item_axis {item: axis} and groups {model: {...}}.

        setting = scale(model) x fineness(coffee, recipe) + offset(grinder)

    The model is the hierarchy: a scale belongs to a grinder model and is learned from all its
    owners together; only the zero belongs to one grinder. So a new owner of a known model
    needs one coffee in common with anyone, not three, and a grinder that is zeroed again
    keeps its scale.

    Nothing needs a grinder marked in microns to start. Where one is linked in, the axis is
    microns (axis 0). Where none is, the axis is relative to a reference model, and carries
    its own id so that it is never mixed with another.
    """
    by_instance = {}
    group_of = {}
    for p in points:
        by_instance.setdefault(p["instance"], []).append(p)
        group_of[p["instance"]] = _group_of(p)
    members = {}
    for g, grp in group_of.items():
        members.setdefault(grp, []).append(g)
    # What the maker says, where an owner gave it: one figure for the model.
    maker = {}
    for grp, gs in members.items():
        given = [1.0 / by_instance[g][0]["um_per_unit"] for g in gs if by_instance[g][0]["um_per_unit"] > 0]
        if given:
            maker[grp] = statistics.median(given)
    # Grinders are linked by the coffees they share.
    parent = {g: g for g in by_instance}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first_of = {}
    for g, ps in by_instance.items():
        for p in ps:
            if p["item"] in first_of:
                a, b = find(first_of[p["item"]]), find(g)
                if a != b:
                    parent[a] = b
            else:
                first_of[p["item"]] = g
    components = {}
    for g in by_instance:
        components.setdefault(find(g), []).append(g)
    result = {"fineness": {}, "scale": {}, "offset": {}, "axis_of": {}, "item_axis": {}, "groups": {}}
    for insts in components.values():
        fineness, scale, offset, axis, groups = _fit_component(insts, by_instance, group_of, maker)
        result["fineness"].update(fineness)
        result["scale"].update(scale)
        result["offset"].update(offset)
        for g in insts:
            result["axis_of"][g] = axis
        for item in fineness:
            result["item_axis"][item] = axis
        for grp, info in groups.items():
            # A model in two separate components is one model; keep the better-founded entry.
            if grp not in result["groups"] or info["instances"] > result["groups"][grp]["instances"]:
                result["groups"][grp] = info
    return result


def fit(points):
    """Returns (fineness {item: value}, scale {instance: a}, offset {instance: b})."""
    r = fit_all(points)
    return r["fineness"], r["scale"], r["offset"]


def flow_refs(observations):
    """For each coffee and recipe, the basis most dial-ins were timed on, and their median flow.
    Fineness is published for that flow; only dial-ins on that basis are normalised to it."""
    groups = {}
    for o in observations:
        if o.get("flow_gs"):
            groups.setdefault(o["item"], []).append(o)
    refs = {}
    for item, os_ in groups.items():
        count = {}
        for o in os_:
            count[o["basis"]] = count.get(o["basis"], 0) + 1
        basis = max(count, key=lambda b: (count[b], b == "total"))
        refs[item] = (basis, math.exp(statistics.median(math.log(o["flow_gs"])
                                                        for o in os_ if o["basis"] == basis)))
    return refs


def _within(values, groups_a, groups_b, rounds=40):
    """`values` with the mean of each group in `groups_a` and in `groups_b` taken out, both at
    once (alternating means converge on it, for data that is not a full grid)."""
    v = list(values)
    for _ in range(rounds):
        for groups in (groups_a, groups_b):
            total, count = {}, {}
            for x, g in zip(v, groups):
                total[g] = total.get(g, 0.0) + x
                count[g] = count.get(g, 0) + 1
            v = [x - total[g] / count[g] for x, g in zip(v, groups)]
    return v


def estimate_kappa(observations, fitted, refs):
    """Axis units of grind per unit of ln(flow), per axis: {axis: {"kappa", "n", "source"}}.

    Within one coffee, an owner who ran faster than another used a coarser grind. The slope of
    grind (in axis units, each grinder's scale taken out) on ln(flow), with each coffee's own
    level AND each grinder's own level removed, is the sensitivity. Taking the grinder's level
    out matters: an owner's habitual flow is indistinguishable from where their zero sits, so
    only how a grinder's flow varies from coffee to coffee can say anything. (The fit's own
    offsets are not used: they have already soaked up part of that.)

    On the microns axis there is always a figure: the prior unless the measured one is
    believable. On a relative axis there is one only when measured, since no prior exists
    in its unit.
    """
    rows = {}
    for o in observations:
        g, item = o["instance"], o["item"]
        if g not in fitted["scale"] or item not in refs or not o.get("flow_gs") or o["basis"] != refs[item][0]:
            continue
        rows.setdefault(fitted["item_axis"][item], []).append(
            (item, g, o["setting"] / fitted["scale"][g], math.log(o["flow_gs"])))
    out = {0: {"kappa": KAPPA_PRIOR_UM, "n": 0, "source": "prior"}}
    for axis, items in rows.items():
        n = len(items)
        if n < KAPPA_MIN_POINTS:
            continue
        us = _within([r[2] for r in items], [r[0] for r in items], [r[1] for r in items])
        xs = _within([r[3] for r in items], [r[0] for r in items], [r[1] for r in items])
        sxx = sum(x * x for x in xs)
        if sxx <= 0 or sxx / n < KAPPA_MIN_SPREAD ** 2:
            continue
        slope = sum(u * x for u, x in zip(us, xs)) / sxx
        if slope <= 0:
            continue
        if axis == 0 and not (KAPPA_PRIOR_UM / KAPPA_PRIOR_BAND <= slope <= KAPPA_PRIOR_UM * KAPPA_PRIOR_BAND):
            out[0]["n"] = n
            continue
        out[axis] = {"kappa": slope, "n": n, "source": "measured"}
    return out


def normalise_flow(observations, fitted, refs, kappa):
    """Move each dial-in to the flow its coffee was typically settled at: a faster shot was
    made at a coarser grind than the one that gives the typical flow, so it is brought finer."""
    out = []
    for o in observations:
        o = dict(o)
        item, g = o["item"], o["instance"]
        k = kappa.get(fitted["item_axis"].get(item))
        if k and g in fitted["scale"] and item in refs and o.get("flow_gs") and o["basis"] == refs[item][0]:
            o["setting"] -= fitted["scale"][g] * k["kappa"] * math.log(o["flow_gs"] / refs[item][1])
        out.append(o)
    return out


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
    """The fit, allowing for age and for how fast each dial-in ran.

    Returns (points, fit, rate, pairs, flow); `fit` is fit_all's result and `flow` is
    {"refs": flow_refs, "kappa": estimate_kappa}.

    A first fit gives every grinder's scale, which is what turns its settings into
    microns; with those the ageing rate is measured. If there is one, each dial-in
    is moved to the age its coffee was typically settled at, so that one made on an
    old bag neither widens the spread nor drags the coffee's figure, and the fit is
    done again. Each point's age_days is then the age its coffee's figure is for.
    The same is then done for flow: the sensitivity is measured on that fit, and each
    dial-in is moved to the flow its coffee was typically settled at.

    Only grinders on the microns axis take part in ageing: a rate in an arbitrary unit
    would mean nothing to anyone on another axis.
    """
    work = observations
    points = collapse(work)
    first = fit_all(points)
    microns = {g: a for g, a in first["scale"].items() if first["axis_of"][g] == 0}
    rate, pairs = age_rate(observations, microns)
    if rate is not None:
        by_item = {}
        for o in observations:
            if o.get("age_days") is not None:
                by_item.setdefault(o["item"], []).append(o["age_days"])
        usual = {item: statistics.median(ages) for item, ages in by_item.items()}
        moved = []
        for o in observations:
            o = dict(o)
            if o.get("age_days") is not None and o["instance"] in microns:
                o["setting"] -= microns[o["instance"]] * rate * (o["age_days"] - usual[o["item"]])
                o["age_days"] = usual[o["item"]]
            moved.append(o)
        work = moved
        points = collapse(work)
        first = fit_all(points)
    refs = flow_refs(work)
    kappa = estimate_kappa(work, first, refs)
    flowed = normalise_flow(work, first, refs, kappa)
    if any(a["setting"] != b["setting"] for a, b in zip(work, flowed)):
        points = collapse(flowed)
        first = fit_all(points)
    return points, first, rate, pairs, {"refs": refs, "kappa": kappa}


def build(root, accept_unsigned=False, min_contributors=2, log=print):
    observations = load_observations(root, accept_unsigned, log)
    points, fitted, rate, pairs, flow = fit_with_age(observations)
    fineness, scale, offset = fitted["fineness"], fitted["scale"], fitted["offset"]
    axis_of, item_axis = fitted["axis_of"], fitted["item_axis"]
    by_item, by_instance = {}, {}
    for p in points:
        by_item.setdefault(p["item"], []).append(p)
        by_instance.setdefault(p["instance"], []).append(p)
    out = os.path.join(root, "index")
    os.makedirs(os.path.join(out, "dialin"), exist_ok=True)
    os.makedirs(os.path.join(out, "fit"), exist_ok=True)

    def write(path, value):
        text = json.dumps(value, separators=(",", ":"), sort_keys=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        # Controllers read an index file into 64 kB: warn well before one stops fitting.
        if len(text.encode("utf-8")) > INDEX_WARN_BYTES:
            log(f"warning: {os.path.relpath(path, root)} is {len(text)} bytes; controllers read at most 65535")

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

    # Coffee ratings.
    write(os.path.join(out, "taste.json"), build_taste(root, min_contributors, log))

    # Subscription services reviewers have listed, and what their users think of them.
    write(os.path.join(out, "services.json"), build_services(root, min_contributors, log))

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
            vr.check_reading(entry)
            if not library_file(entry.get("id")) or "/" in entry["id"]:
                raise vr.Refused("id is not a plain lower-case name")
            # The setting's range, in stored steps, where it is given.
            if "min" in entry or "max" in entry:
                vr._number(entry, "min", 1, 2000)
                vr._number(entry, "max", 1, 2000)
                if entry["min"] >= entry["max"]:
                    raise vr.Refused("min is not below max")
            listed.append({k: entry[k] for k in ("id", "model", "burrs", "unit", "um_per_unit", "divisor", "sub_steps",
                                                 "min", "max") if k in entry})
        except (vr.Refused, ValueError, OSError, AttributeError, TypeError) as error:
            log(f"grinder entry ignored: {path}: {error}")
    write(os.path.join(out, "grinders.json"), {"v": 1, "grinders": listed})

    # Espresso machine profiles reviewers have listed: a machine, a control, and how it is worked.
    machines = []
    for path in sorted(glob.glob(os.path.join(root, "machines", "*.json"))):
        try:
            entry = read_json(path)
            vr.check_machine(entry)
            if not library_file(entry.get("id")) or "/" in entry["id"] or len(entry["id"]) > 39:
                raise vr.Refused("id is not a plain lower-case name of at most 39 characters")
            machines.append({k: entry[k] for k in ("id", "maker", "model", "control", "style", "manual_start",
                                                    "hold_preinfusion", "tap_preinfusion", "power_toggle",
                                                    "self_stop_s") if k in entry})
        except (vr.Refused, ValueError, OSError, AttributeError, TypeError, KeyError) as error:
            log(f"machine entry ignored: {path}: {error}")
    write(os.path.join(out, "machines.json"), {"v": 1, "machines": machines})

    def model_spread(model, unit, by_owner):
        """How far owners of this model sit from each other: on this coffee if three or more
        did it, else from where their zeros sit over everything they have shared."""
        spread = zero_spread(list(by_owner.values()))
        if spread is None:
            spread = (fitted["groups"].get((model, unit)) or {}).get("offset_spread")
        return {"spread": round(spread, 2)} if spread is not None else {}

    # What was settled on, per coffee.
    per_coffee = {}
    for item, ps in by_item.items():
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
        # Same-model medians need no fit: they are published for a coffee the fit cannot place
        # (no grinder in reach of a scale), so owners of one model still help each other.
        placed = item in fineness
        per_coffee.setdefault(library_id, []).append({
            "dose_g": dose, "yield_g": yield_g,
            "contributors": len(contributors),
            "dialins": sum(p["count"] for p in ps),
            "time_s": round(statistics.median(p["time_s"] for p in ps), 1),
            **({"age_days": round(statistics.median(a))} if (a := [p["age_days"] for p in ps
                                                            if p.get("age_days") is not None]) else {}),
            # `fineness_um` is in microns when `axis` is absent; with an `axis` it is in that
            # axis' own unit and only fits that axis' grinders (index/fit). Same key, so older
            # firmware keeps reading it; it ignores `axis` and so must not be offered those.
            **({"fineness_um": round(fineness[item], 1),
                "spread_um": round(1.4826 * statistics.median(residuals), 1) if len(residuals) > 1 else 0}
               if placed else {}),
            **({"axis": item_axis[item]} if placed and item_axis[item] else {}),
            **({"flow_gs": round(flow["refs"][item][1], 2), "flow_basis": flow["refs"][item][0]}
               if item in flow["refs"] else {}),
            **({"kappa": round(flow["kappa"][item_axis[item]]["kappa"], 1)}
               if placed and item_axis[item] in flow["kappa"] else {}),
            "models": [dict({"library_id": m} if isinstance(m, str) else {"model_id": m}, unit=u,
                            median=round(statistics.median(v.values()), 1), n=len(v),
                            **model_spread(m, u, v))
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
            "coffees_in_common": common, **({"axis": axis_of[g]} if axis_of[g] else {})})
    for kid, grinders in per_kid.items():
        write(os.path.join(out, "fit", kid + ".json"),
              {"v": 1, "grinders": sorted(grinders, key=lambda x: x["calibration"])})
    # What the fit has learned about each grinder model: units of its dial per micron (or per
    # unit of its axis), from all its owners together. Where the axis is microns, the figure a
    # reviewer can check against the maker's: microns of burr gap per unit.
    models_out = []
    for grp, info in sorted(fitted["groups"].items(), key=lambda kv: str(kv[0])):
        if grp[0] == "own":
            continue
        key, unit = grp
        entry = dict({"library_id": key} if isinstance(key, str) else {"model_id": key}, unit=unit,
                     scale=round(info["scale"], 5), owners=info["instances"],
                     source="maker" if info["known"] else "fitted")
        if info.get("offset_spread") is not None:
            entry["zero_spread"] = round(info["offset_spread"], 2)
        if info.get("offset_zero") is not None:
            entry["zero"] = round(info["offset_zero"], 2)
            entry["zero_n"] = info["offset_n"]
        if info["axis"]:
            entry["axis"] = info["axis"]
        else:
            entry["um_per_unit"] = round(1.0 / info["scale"], 3)
        models_out.append(entry)
    write(os.path.join(out, "models.json"), {"v": 1, "models": models_out})
    write(os.path.join(out, "flow.json"), {"v": 1, "sensitivity": [
        {"axis": a, "kappa": round(k["kappa"], 2), "n": k["n"], "source": k["source"]}
        for a, k in sorted(flow["kappa"].items())]})
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
    "cara": (0x3333, {"model": "Example stepped grinder", "unit": "steps", "um_per_unit": 5}, 0.2, 2.0,
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


def make_example(root, log=print, people=None):
    """Four invented contributors with real signatures (throwaway keys), four coffees."""
    def put(path, text):
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    for coffee in EXAMPLE_COFFEES:
        put(os.path.join("catalog", coffee["id"] + ".json"), json.dumps(coffee, indent=1))
    truth = {}
    for name, (private, grinder, a, b, coffees) in (people or EXAMPLE_PEOPLE).items():
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
    # 00. Different ways of reading a dial are different units.
    assert unit_key({"unit": "dial"}) == "dial"
    assert unit_key({"unit": "dial", "divisor": 1}) == "dial"
    assert unit_key({"unit": "dial", "divisor": 10}) == "dial/d10"
    assert unit_key({"unit": "sette", "sub_steps": 9}) == "sette/r9"
    # 0. Age counts days off roast less days in the freezer.
    aged = {"at": "2026-10-31T08:00:00Z", "roast_date": "2026-10-01"}
    assert age_days(aged) == 30
    assert age_days(dict(aged, frozen_days=20)) == 12         # 20 of the 30 days frozen: 18 of them do not count
    assert age_days(dict(aged, frozen_days=99)) == 3          # more than it was old: capped at its age, not negative
    assert age_days(dict(aged, frozen_days=0)) == 30
    assert age_days(dict(aged, frozen_days="x")) == 30        # nonsense is ignored, not trusted
    assert age_days({"at": "2026-10-31T08:00:00Z"}) is None   # no roast date, no age
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


    # 1c. Nobody needs a grinder marked in microns. Three owners of one unmarked model, and
    #     a second unmarked model linked to them, fit on a relative axis.
    NICHE, DF = (0.2, ("niche", "dial")), (0.25, ("df64", "dial"))
    owners = {"n1": (NICHE, 4.0), "n2": (NICHE, -6.0), "n3": (NICHE, 11.0),
              "d1": (DF, 9.0), "d2": (DF, -3.0)}
    fin = {"c1": 250.0, "c2": 236.0, "c3": 266.0, "c4": 228.0, "c5": 242.0}

    def point(who, coffee, cal=0, marked=0):
        (a, model), b = owners[who]
        return {"kid": who, "instance": (who, cal), "unit": model[1], "model_id": 0, "model_key": model[0],
                "um_per_unit": marked, "item": (coffee, (18.0, 36)), "setting": a * fin[coffee] + b,
                "time_s": 26.0, "count": 1}

    rel = [point(w, c) for w in ("n1", "n2", "n3") for c in fin if (w, c) != ("n3", "c5")]
    rel += [point("d1", c) for c in ("c1", "c2", "c3", "c4")] + [point("d2", "c1")]
    r = fit_all(rel)
    assert len(set(r["axis_of"].values())) == 1 and next(iter(r["axis_of"].values())) != 0, r["axis_of"]
    for who in owners:
        (a, _), b = owners[who]
        if (who, 0) not in r["scale"]:
            raise AssertionError(f"{who} was not placed")
    # The two models' scales stand in the right proportion, whichever is the reference.
    ratio = r["scale"][("d1", 0)] / r["scale"][("n1", 0)]
    assert abs(ratio - 0.25 / 0.2) < 1e-6, ratio
    # A held-back coffee (n3 never dialled c5) is predicted from n3's zero and the others' c5.
    ((a3, _), b3) = owners["n3"]
    predicted = r["scale"][("n3", 0)] * r["fineness"][("c5", (18.0, 36))] + r["offset"][("n3", 0)]
    assert abs(predicted - (a3 * fin["c5"] + b3)) < 1e-6, predicted
    # d2 has only ONE coffee in common, yet its model's scale (learned from d1) places it,
    # and it gets a setting for a coffee it never dialled.
    ((a4, _), b4) = owners["d2"]
    predicted = r["scale"][("d2", 0)] * r["fineness"][("c3", (18.0, 36))] + r["offset"][("d2", 0)]
    assert abs(predicted - (a4 * fin["c3"] + b4)) < 1e-6, predicted
    # Zeroed again: a new calibration keeps its model's scale and needs one coffee for its zero.
    again = rel + [dict(point("n1", "c2", cal=1), setting=0.2 * 236.0 + 30.0)]
    r2 = fit_all(again)
    assert abs(r2["scale"][("n1", 1)] - r2["scale"][("n1", 0)]) < 1e-9
    placed = r2["scale"][("n1", 1)] * r2["fineness"][("c2", (18.0, 36))] + r2["offset"][("n1", 1)]
    assert abs(placed - (0.2 * 236.0 + 30.0)) < 1e-6, placed
    # One marked grinder linked in turns the whole axis into microns; two unlinked groups stay apart.
    marked = rel + [point("n1", c, cal=7, marked=5.0) for c in ("c1", "c2")]
    assert set(fit_all(marked)["axis_of"].values()) == {0}
    apart = rel + [dict(point("n1", c), kid="z", instance=("z", 0), item=("other/" + c, (18.0, 36)),
                        unit="steps", model_key="stepped") for c in fin]
    axes = fit_all(apart)["axis_of"]
    assert axes[("z", 0)] != axes[("n1", 0)] and 0 not in axes.values(), axes
    # An owner of an unmarked model with two coffees and nobody else of that model is left out.
    lone = [p for p in rel if p["kid"] != "d2" and not (p["kid"] == "d1" and p["item"][0] not in ("c1", "c2"))]
    assert ("d1", 0) not in fit_all(lone)["scale"]


    # 1d. Flow. Owners who aim at different brew speeds settle at different grinds for the
    #     same coffee. The sensitivity is measured from that, and each dial-in is moved to the
    #     coffee's typical flow, so the owners agree again.
    KAPPA = 70.0
    flows = {"f1": 1.0, "f2": 1.3, "f3": 0.8, "f4": 1.1, "f5": 1.5, "f6": 0.9}
    coffees = {"c1": 250.0, "c2": 236.0, "c3": 266.0, "c4": 228.0}

    def flow_obs(owners_flows, coffees_used):
        # Each owner has a habitual flow and strays from it by coffee: only the straying says
        # what a change of flow is worth (the habit alone is indistinguishable from the zero).
        out = []
        for i, (who, habit) in enumerate(owners_flows.items()):
            for j, c in enumerate(coffees_used):
                phi = habit * (1.0, 1.2, 0.85, 1.1)[(i + j) % 4]
                setting = 1.0 * (coffees[c] + KAPPA * math.log(phi / 1.1)) + (3.0 if who in ("f2", "f4") else -2.0)
                out.append({"kid": who, "instance": (who, 0), "unit": "um", "model_id": 1, "model_key": 1,
                            "um_per_unit": 1.0, "item": (c, (18.0, 36)), "setting": setting, "time_s": 36.0 / phi,
                            "basis": "total", "flow_gs": phi, "age_days": None})
        return out

    many = flow_obs(flows, coffees)
    pts, fitted, rate, pairs, flow = fit_with_age(many)
    k = flow["kappa"][0]
    assert k["source"] == "measured" and abs(k["kappa"] - KAPPA) < 3.0, k
    spread = max(abs(p["setting"] - fitted["offset"][p["instance"]] - fitted["fineness"][p["item"]])
                 for p in pts)
    assert spread < 2.0, spread        # without the move they sit further apart (below)
    raw = fit_all(collapse(many))
    raw_spread = max(abs(p["setting"] - raw["offset"][p["instance"]] - raw["fineness"][p["item"]])
                     for p in collapse(many))
    assert raw_spread > 5, raw_spread
    # Too little to measure: the prior, and nothing is invented on a relative axis.
    few = flow_obs({"f1": 1.0, "f2": 1.3}, ["c1", "c2"])
    assert fit_with_age(few)[4]["kappa"][0]["source"] == "prior"
    rel_few = [dict(o, um_per_unit=0, model_id=0, model_key=0) for o in few]
    assert list(fit_with_age(rel_few)[4]["kappa"]) == [0]
    # A slope far outside what a grinder can do is noise, not a measurement.
    wild = [dict(o, setting=o["setting"] * (1 if o["kid"] != "f2" else 1) + (500 if o["kid"] == "f5" else 0))
            for o in many]
    assert fit_with_age(wild)[4]["kappa"][0]["kappa"] <= KAPPA * 4 * 1.0001

    # 2. End to end: signed example records in, index files out.
    with tempfile.TemporaryDirectory() as root:
        true_settings = make_example(root, log=lambda *_: None)
        build(root, log=lambda *_: None)
        index = read_json(os.path.join(root, "index", "coffees.json"))
        assert len(index["coffees"]) == 4
        # Coffee ratings: a coffee rated by two contributors is published, one rated by one is not;
        # a drinker with three of the published coffees rated is listed, anonymously.
        def kid_of(private):
            point = vr._mul(private, vr.G)
            return vr.key_id(b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big"))
        tastes = {"anna": [("portrait/idjwi-island", 5, ["fruity", "floral"]), ("example/ethiopia-guji", 4, ["floral"]),
                           ("example/kenya-aa", 5, ["fruity"])],
                  "ben": [("portrait/idjwi-island", 3, ["chocolate"]), ("example/ethiopia-guji", 5, ["floral", "fruity"]),
                          ("example/kenya-aa", 2, [])],
                  "cara": [("example/colombia-decaf", 4, ["chocolate"])]}
        for name, rated in tastes.items():
            private = EXAMPLE_PEOPLE[name][0]
            kid = kid_of(private)
            for n, (library_id, stars, flavours) in enumerate(rated, start=1):
                entry = next(c for c in EXAMPLE_COFFEES if c["id"] == library_id)
                body = {"t": "taste", "v": 1, "id": n, "at": "2026-10-21T08:00:00Z",
                        "coffee": {"library_id": library_id, "name": entry["name"]},
                        "drinker": 1, "stars": stars, "cup": {"acidity": 3 + n % 3}, "flavours": flavours}
                vr.check_body(body)
                os.makedirs(os.path.join(root, "tastes"), exist_ok=True)
                with open(os.path.join(root, "tastes", f"{kid}-r{n}.json"), "w", encoding="utf-8") as f:
                    f.write(_envelope(private, kid, body))
        build(root, log=lambda *_: None)
        taste = read_json(os.path.join(root, "index", "taste.json"))
        assert set(taste["coffees"]) == {"portrait/idjwi-island", "example/ethiopia-guji", "example/kenya-aa"}, taste
        assert taste["coffees"]["example/ethiopia-guji"]["stars"] == 4.5
        assert taste["coffees"]["example/ethiopia-guji"]["flavours"]["floral"] == 1.0
        assert taste["coffees"]["portrait/idjwi-island"]["stars_hist"] == [0, 0, 1, 0, 1]
        assert len(taste["people"]) == 2 and all(len(p["r"]) == 3 for p in taste["people"])
        assert all("anna" not in json.dumps(p) for p in taste["people"])
        # Subscription services: listed by a reviewer; reviewed by two contributors (published) and the
        # coffees they sent rated by two (a service taste, and each drinker's liking for it).
        os.makedirs(os.path.join(root, "services"), exist_ok=True)
        with open(os.path.join(root, "services", "trade-coffee.json"), "w", encoding="utf-8") as f:
            json.dump({"id": "trade-coffee", "name": "Trade Coffee", "url": "https://www.drinktrade.com/",
                       "kind": "coffee", "ships_to": ["US"], "sourcing": ["fair_trade"]}, f)
        with open(os.path.join(root, "services", "Bad Name.json"), "w", encoding="utf-8") as f:
            json.dump({"id": "Bad Name", "name": "x", "url": "https://x.example/", "kind": "coffee"}, f)
        os.makedirs(os.path.join(root, "svcreviews"), exist_ok=True)
        for name, stars, value in (("anna", 5, 4), ("ben", 3, 2), ("cara", 4, None)):
            private = EXAMPLE_PEOPLE[name][0]
            kid = kid_of(private)
            body = {"t": "service_review", "v": 1, "id": 1, "service": "trade-coffee", "drinker": 1, "stars": stars,
                    "aspects": {"value": value} if value else {}}
            with open(os.path.join(root, "svcreviews", f"{kid}-v1.json"), "w", encoding="utf-8") as f:
                f.write(_envelope(private, kid, body))
        for name in ("anna", "ben"):
            private = EXAMPLE_PEOPLE[name][0]
            kid = kid_of(private)
            path = os.path.join(root, "tastes", f"{kid}-r1.json")
            with open(path, encoding="utf-8") as f:
                body = json.loads(json.loads(f.read())["body"])
            body["service"] = "trade-coffee"
            with open(path, "w", encoding="utf-8") as f:
                f.write(_envelope(private, kid, body))
        build(root, log=lambda *_: None)
        services = read_json(os.path.join(root, "index", "services.json"))["services"]
        assert [s["id"] for s in services] == ["trade-coffee"], services
        assert services[0]["reviews"]["n"] == 3 and services[0]["reviews"]["stars"] == 4.0
        assert services[0]["reviews"]["aspects"] == {"value": 3.0}, services[0]["reviews"]
        taste = read_json(os.path.join(root, "index", "taste.json"))
        assert taste["services"]["trade-coffee"]["n"] == 2 and taste["services"]["trade-coffee"]["stars"] == 4.0
        likes = sorted(p["r"].get("svc:trade-coffee") for p in taste["people"])
        assert likes == [3, 5], taste["people"]
        assert len(taste["people"]) == 2
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
    # 3. No grinder marked in microns anywhere. Three Niche owners, and two DF64 owners of whom
    #    one is linked by a coffee and the other only shares a coffee with him (so nothing can
    #    be fitted for it): the first coffees still get figures, and the last gets the owners' median.
    cs = ["portrait/idjwi-island", "example/ethiopia-guji", "example/colombia-decaf", "example/kenya-aa"]
    niche = {"model_id": 5, "model": "Niche Zero", "unit": "dial"}
    df = {"model_id": 3, "model": "DF64", "unit": "dial"}
    people = {"n1": (0x5101, niche, 0.2, 4.0, cs[:3]), "n2": (0x5102, niche, 0.2, -6.0, cs[:3]),
              "n3": (0x5103, niche, 0.2, 11.0, cs[:3]),
              "d1": (0x5104, df, 0.25, 9.0, [cs[0], cs[3]]), "d2": (0x5105, df, 0.25, -3.0, [cs[3]])}
    with tempfile.TemporaryDirectory() as root:
        make_example(root, log=lambda *_: None, people=people)
        build(root, log=lambda *_: None)
        first = read_json(os.path.join(root, "index", "dialin", "portrait__idjwi-island.json"))["recipes"][0]
        assert "fineness_um" in first and first["axis"] != 0, first
        last = read_json(os.path.join(root, "index", "dialin", "example__kenya-aa.json"))["recipes"][0]
        assert "fineness_um" not in last and "axis" not in last, last   # nothing to place it by
        assert last["contributors"] == 2
        assert [m for m in last["models"] if m["model_id"] == 3][0]["n"] == 2   # but their median is there
        fits = [read_json(os.path.join(root, "index", "fit", k))["grinders"][0]
                for k in os.listdir(os.path.join(root, "index", "fit"))]
        assert fits and all(f["axis"] == first["axis"] for f in fits), fits
        models = {(m.get("model_id"), m["unit"]): m for m in
                  read_json(os.path.join(root, "index", "models.json"))["models"]}
        assert models[(5, "dial")]["source"] == "fitted" and "um_per_unit" not in models[(5, "dial")]
        assert "age_days" not in read_json(os.path.join(root, "index", "age.json"))   # no micron axis: no rate
        # Flow and spread reach the files the controller reads.
        assert first["flow_basis"] == "total" and first["flow_gs"] > 0, first
        assert "kappa" not in first                      # too little to measure on a relative axis
        niche_m = [m for m in first["models"] if m["model_id"] == 5][0]
        assert niche_m["n"] == 3 and "spread" in niche_m, niche_m          # three owners: a spread
        df_m = [m for m in last["models"] if m["model_id"] == 3][0]
        assert "spread" not in df_m                      # two owners and no model-wide figure: none claimed
        sens = read_json(os.path.join(root, "index", "flow.json"))["sensitivity"]
        assert sens == [{"axis": 0, "kappa": 84.0, "n": 0, "source": "prior"}], sens
    # 4. One model, one key: three Niche owners, one whose records name the grinder only by the
    #    firmware's number (5), two by the library's entry for it, which lists that number. They
    #    pool into one model, whose typical zero is published, and that zero with the model's scale
    #    places a coffee for an owner who has none in common with anyone (a new owner).
    niche_number = {"model_id": 5, "model": "Niche Zero", "unit": "dial"}
    niche_entry = {"model_id": 5, "library_id": "niche-zero", "model": "Niche Zero", "unit": "dial"}
    people = {"m1": (0x5201, niche_number, 0.2, 4.0, cs[:3]), "m2": (0x5202, niche_entry, 0.2, -6.0, cs[:3]),
              "m3": (0x5203, niche_entry, 0.2, 11.0, cs[:3])}
    with tempfile.TemporaryDirectory() as root:
        truth = make_example(root, log=lambda *_: None, people=people)
        os.makedirs(os.path.join(root, "grinders"), exist_ok=True)
        with open(os.path.join(root, "grinders", "niche-zero.json"), "w", encoding="utf-8") as f:
            json.dump({"id": "niche-zero", "model": "Niche Zero", "unit": "dial", "model_id": 5}, f)
        build(root, log=lambda *_: None)
        models = read_json(os.path.join(root, "index", "models.json"))["models"]
        niche_models = [m for m in models if m.get("library_id") == "niche-zero" or m.get("model_id") == 5]
        assert len(niche_models) == 1 and niche_models[0].get("library_id") == "niche-zero", models
        nm = niche_models[0]
        assert nm["owners"] == 3 and nm["zero_n"] == 3 and "zero" in nm, nm
        # The median owner (offset 4) is where a new owner is placed: within a step of his setting.
        first = read_json(os.path.join(root, "index", "dialin", "portrait__idjwi-island.json"))["recipes"][0]
        m1 = kid_of(0x5201)
        placed = nm["scale"] * first["fineness_um"] + nm["zero"]
        assert abs(placed - truth[(m1, "portrait/idjwi-island")]) <= 1.5, (placed, truth)
    # 5. A model fitted for one grinder only gives no zero: one grinder's zero is not the model's.
    people = {"o1": (0x5301, niche_entry, 0.2, 4.0, cs[:3]),
              "o2": (0x5302, {"model_id": 3, "model": "DF64", "unit": "dial"}, 0.25, 9.0, cs[:3])}
    with tempfile.TemporaryDirectory() as root:
        make_example(root, log=lambda *_: None, people=people)
        build(root, log=lambda *_: None)
        for m in read_json(os.path.join(root, "index", "models.json"))["models"]:
            assert "zero" not in m, m
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
