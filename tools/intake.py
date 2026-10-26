#!/usr/bin/env python3
"""Take in what controllers have sent: check every record, file the good
ones, and put coffees up for review.

    python tools/intake.py take --inbox <folder> --library <folder> [--plan plan.json] [--summary file.md]
    python tools/intake.py resolve --library <folder> --kid K --local-id N --record R
                                   --state published|declined [--library-id ID] [--note TEXT]
    python tools/intake.py --self-test

Controllers push signed records into the inbox. Nothing there is trusted:
not the file names, not the folders, only what passes the checks in
tools/verify_record.py:

  1. the envelope is well formed;
  2. the signature is right for the body, with a key on file (records are
     signed, not encrypted: anyone can read one, nobody can alter one);
  3. every value is of the expected type and inside the range the firmware
     allows.

What happens to a record that passes depends on what it is:

  key      filed under keys/. A key says nothing by itself.
  dial-in  filed under dialins/. A measurement: checked, not reviewed.
  shot     filed under shots/. The same.
  taste    a coffee rating, filed under tastes/ (a changed rating replaces the earlier one).
  service_review  a rating of a listed subscription service, filed under svcreviews/ (the same).
  grinder, machine, service  descriptions for the shared lists: reviewed, like a coffee.
  coffee   NOT published. It is parked under pending/, the contributor's
           status file says "review", and the plan lists a pull request to
           open that would add it to catalog/. A person decides.

A record that fails is left out and listed, with the reason, in the summary.

`take` changes only files under the library folder and writes the plan; the
workflow does the committing and opens the pull requests. `resolve` records
a reviewer's decision in the contributor's status file.
"""
import argparse
import difflib
import glob
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_record as vr  # noqa: E402

CATALOG_FIELDS = ("name", "roaster", "origin", "region", "producer", "varietal", "process",
                  "roast_level", "altitude_m", "notes")
GRINDER_FIELDS = ("model", "burrs", "unit", "um_per_unit", "divisor", "sub_steps")
MACHINE_FIELDS = ("maker", "model", "control", "style", "manual_start", "hold_preinfusion",
                  "tap_preinfusion", "power_toggle", "self_stop_s")
SERVICE_FIELDS = ("name", "url", "manage_url", "platform", "kind", "ships_to", "cadences", "price_from_cents",
                  "currency", "style", "sourcing", "image", "icon", "color", "about")
NOTE_LIMIT = 47     # what the controller keeps of a reviewer's note
MAX_RECORD_BYTES = 8192


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")


CATALOG_ID_MAX = 39  # the controller keeps 39 characters of a library id (LIBRARY_ID_LEN)


def catalog_id(coffee):
    roaster = (slug(coffee.get("roaster")) or "unknown")[:20].strip("-") or "unknown"
    name = slug(coffee["name"]) or "unnamed"
    name = name[:CATALOG_ID_MAX - len(roaster) - 1].strip("-") or "unnamed"
    return f"{roaster}/{name}"


def month_folder(body):
    at = body.get("at", "")
    return f"{at[0:4]}/{at[5:7]}" if re.match(r"^\d{4}-\d{2}-\d{2}T", at) else "undated"


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def set_status(library, kid, local_id, record, state, library_id="", note="", section="coffees"):
    """One line per coffee (or grinder) in status/<kid>.json; a newer record replaces an older one's line."""
    path = os.path.join(library, "status", kid + ".json")
    status = read_json(path, {}) or {}
    if not isinstance(status, dict):
        status = {}
    entries = [e for e in status.get(section, []) if isinstance(e, dict)]
    current = next((e for e in entries if e.get("local_id") == local_id), None)
    if current and current.get("record", -1) > record:
        return False    # the contributor has sent a newer version since
    entry = {"local_id": local_id, "record": record, "state": state}
    if library_id:
        entry["library_id"] = library_id
    note = "".join(c for c in (note or "") if 0x20 <= ord(c) <= 0x7E)[:NOTE_LIMIT].strip()
    if note:
        entry["note"] = note
    entries = [e for e in entries if e.get("local_id") != local_id] + [entry]
    entries.sort(key=lambda e: e.get("local_id", 0))
    status["v"] = 1
    status.setdefault("coffees", [])
    status[section] = entries
    write_text(path, json.dumps(status, separators=(",", ":"), sort_keys=True) + "\n")
    return True


STATUS_SECTIONS = {"coffee": "coffees", "grinder": "grinders", "machine": "machines", "service": "services"}


def tell_refused(library, error):
    """A coffee, grinder or machine record signed by a key on file but refused for what it says: its
    line in the contributor's status file says so, with the reason, so that the controller can show it
    and offer to send the item again. Anything not signed by a key on file tells no one anything."""
    kid, body = getattr(error, "kid", None), getattr(error, "body", None)
    if not kid or not isinstance(body, dict):
        return False
    section = STATUS_SECTIONS.get(body.get("t"))
    local_id, record = body.get("local_id"), body.get("record")
    if not section or not all(isinstance(v, int) and not isinstance(v, bool) and 0 < v < 2 ** 32
                              for v in (local_id, record)):
        return False
    return set_status(library, kid, local_id, record, "refused", note=str(error), section=section)


def similar_coffees(library, coffee):
    """Catalog entries a reviewer should look at before adding this one."""
    wanted = f"{coffee.get('roaster', '')} {coffee['name']}".lower().strip()
    existing = {}
    for path in glob.glob(os.path.join(library, "catalog", "**", "*.json"), recursive=True):
        entry = read_json(path)
        if isinstance(entry, dict) and entry.get("id") and entry.get("name"):
            existing[f"{entry.get('roaster', '')} {entry['name']}".lower().strip()] = entry["id"]
    close = difflib.get_close_matches(wanted, list(existing), n=5, cutoff=0.6)
    name = coffee["name"].lower()
    close += [k for k in existing if name in k and k not in close][:5]
    return [existing[k] for k in close]


def contributor_history(library, kid):
    count = 0
    for folder in ("dialins", "shots"):
        count += len(glob.glob(os.path.join(library, folder, "**", kid + "-*.json"), recursive=True))
    return count


def pull_request_text(library, kid, body, proposed_id, exists):
    rows = "\n".join(f"| {field.replace('_', ' ')} | {body[field]} |" for field in CATALOG_FIELDS if field in body)
    similar = [s for s in similar_coffees(library, body) if s != proposed_id]
    history = contributor_history(library, kid)
    meta = json.dumps({"kind": "coffee", "kid": kid, "local_id": body["local_id"], "record": body["record"],
                       "library_id": proposed_id}, separators=(",", ":"))
    lines = [
        f"A controller has sent this coffee{' again, changed' if exists else ''}. Its record passed the "
        "signature and value checks; whether it belongs in the library is for a person to decide.",
        "",
        "| | |", "| --- | --- |", rows,
        "",
        f"**Would be published as** `{proposed_id}`" + (" (this entry exists: merging replaces it)" if exists else ""),
        "",
        f"**From** key `{kid}`: " + (f"{history} measurements on file from this controller."
                                     if history else "nothing else on file from this controller yet."),
        "",
        "**Similar entries already in the library:** " + (", ".join(f"`{s}`" for s in similar) if similar else "none found."),
        "",
        "- **Merge** to publish. Edit the file in this pull request first if a name or detail needs tidying.",
        "- **Close** to decline. A last comment starting `Declined:` is shown to the contributor "
        f"(first {NOTE_LIMIT} characters).",
        "",
        f"<!-- intake {meta} -->",
    ]
    return "\n".join(lines)


def machine_request_text(library, kid, body, proposed_id, exists):
    rows = "\n".join(f"| {field.replace('_', ' ')} | {body[field]} |" for field in MACHINE_FIELDS if field in body)
    existing = sorted(os.path.splitext(os.path.basename(p))[0]
                      for p in glob.glob(os.path.join(library, "machines", "*.json")))
    close = [e for e in difflib.get_close_matches(proposed_id, existing, n=5, cutoff=0.5) if e != proposed_id]
    meta = json.dumps({"kind": "machine", "kid": kid, "local_id": body["local_id"], "record": body["record"],
                       "library_id": proposed_id}, separators=(",", ":"))
    return "\n".join([
        f"A controller's owner has set up this espresso machine{' again, changed' if exists else ''}. Its record "
        "passed the signature and value checks; whether the rules are right for this machine and this control "
        "is for a person to decide. The same machine worked by another button or lever is another entry.",
        "", "| | |", "| --- | --- |", rows, "",
        f"**Would be listed as** `{proposed_id}`" + (" (this entry exists: merging replaces it)" if exists else ""),
        "",
        "Style: `toggle_button` (one press starts, one stops: the bot does both), `start_button` (the bot starts, "
        "the machine stops itself), `start_stop_buttons` (one bot on start, another on stop), `hold_button` (the "
        "bot holds the button for the whole shot), `manual` (lever, knob, wheel or paddle: nothing is pressed).",
        "",
        "To decline, close this request with a comment starting `declined:`; what follows is shown to the owner.",
        "",
        ("Entries with a similar name: " + ", ".join(f"`{e}`" for e in close)) if close else
        "No entry with a similar name.",
        "",
        f"<!-- intake {meta} -->",
    ])


def service_request_text(library, kid, body, proposed_id, exists):
    def shown(value):
        return ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
    rows = "\n".join(f"| {field.replace('_', ' ')} | {shown(body[field])} |" for field in SERVICE_FIELDS
                     if field in body and field not in ("image", "icon"))
    existing = sorted(os.path.splitext(os.path.basename(p))[0]
                      for p in glob.glob(os.path.join(library, "services", "*.json")))
    close = [e for e in difflib.get_close_matches(proposed_id, existing, n=5, cutoff=0.5) if e != proposed_id]
    host = re.sub(r"^https://(www\.)?", "", body["url"]).split("/")[0]
    same_host = []
    for path in glob.glob(os.path.join(library, "services", "*.json")):
        entry = read_json(path, {}) or {}
        if isinstance(entry, dict) and host and host in str(entry.get("url", "")):
            same_host.append(os.path.splitext(os.path.basename(path))[0])
    claims = body.get("sourcing", [])
    meta = json.dumps({"kind": "service", "kid": kid, "local_id": body["local_id"], "record": body["record"],
                       "library_id": proposed_id}, separators=(",", ":"))
    return "\n".join([
        f"A controller's owner has set up this subscription service{' again, changed' if exists else ''}. Its "
        "record passed the signature and value checks; whether it belongs in the shared list, and whether its "
        "links and claims are right, is for a person to decide.",
        "", "| | |", "| --- | --- |", rows, "",
        f"**Would be listed as** `{proposed_id}`" + (" (this entry exists: merging replaces it)" if exists else ""),
        "",
        "**Check against the service's own site:** the links open the shop and its subscription page; where it "
        "ships; " + ("and each sourcing claim (" + ", ".join(f"`{c}`" for c in claims) + "): remove any it does "
                     "not show evidence for (a certification, named farms, published prices)." if claims else
                     "it makes no sourcing claims."),
        "",
        "**Similar entries already listed:** " + (", ".join(f"`{s}`" for s in sorted(set(close + same_host))) or
                                                   "none found."),
        "",
        "- **Merge** to list it. Edit the file in this pull request first if anything needs correcting.",
        f"- **Close** to decline. A last comment starting `Declined:` is shown to the contributor (first {NOTE_LIMIT} characters).",
        "",
        f"<!-- intake {meta} -->",
    ])


def grinder_request_text(library, kid, body, proposed_id, exists):
    rows = "\n".join(f"| {field.replace('_', ' ')} | {body[field]} |" for field in GRINDER_FIELDS if field in body)
    existing = sorted(os.path.splitext(os.path.basename(p))[0]
                      for p in glob.glob(os.path.join(library, "grinders", "*.json")))
    close = [e for e in difflib.get_close_matches(proposed_id, existing, n=5, cutoff=0.5) if e != proposed_id]
    meta = json.dumps({"kind": "grinder", "kid": kid, "local_id": body["local_id"], "record": body["record"],
                       "library_id": proposed_id}, separators=(",", ":"))
    return "\n".join([
        f"A controller's owner has described this grinder{' again, changed' if exists else ''}. Its record passed "
        "the signature and value checks; whether the model belongs in the shared list, and whether the unit and "
        "the microns per unit are right, is for a person to decide.",
        "", "| | |", "| --- | --- |", rows, "",
        f"**Would be listed as** `{proposed_id}`" + (" (this entry exists: merging replaces it)" if exists else ""),
        "",
        "`um per unit` is how many microns of burr gap one unit of the setting is. Leave it out unless the maker "
        "publishes it: the index then learns the scale from shared shots.",
        "",
        "**Similar entries already listed:** " + (", ".join(f"`{s}`" for s in close) if close else "none found."),
        "",
        "- **Merge** to list it. Edit the file in this pull request first if anything needs correcting.",
        f"- **Close** to decline. A last comment starting `Declined:` is shown to the contributor (first {NOTE_LIMIT} characters).",
        "",
        f"<!-- intake {meta} -->",
    ])


def take(inbox, library, log=print):
    """Returns (plan, report). plan: pull requests to open. report: what happened to each file."""
    keys = vr.load_keys(os.path.join(library, "keys"))
    files = sorted(glob.glob(os.path.join(inbox, "**", "*.json"), recursive=True))
    loaded = []
    for path in files:
        try:
            if os.path.getsize(path) > MAX_RECORD_BYTES:
                raise ValueError("too large to be a record")
            with open(path, encoding="utf-8") as f:
                text = f.read()
            is_key = '\\"t\\":\\"key\\"' in text
        except (OSError, ValueError) as error:
            loaded.append((path, None, str(error), False))
            continue
        loaded.append((path, text, None, is_key))
    # Keys first: the rest of a batch needs them. Then by the sender's record number, so that of two
    # versions of one rating in a batch the later is filed last and stays.
    def order(item):
        number = re.search(r"-(\d+)\.json$", item[0])
        return (not item[3], int(number.group(1)) if number else 0, item[0])
    loaded.sort(key=order)

    plan, report = [], []
    for path, text, problem, _ in loaded:
        shown = os.path.relpath(path, inbox).replace("\\", "/")
        if problem:
            report.append((shown, "refused", problem))
            continue
        try:
            kind, kid, body = vr.verify(text, keys)
        except vr.Refused as error:
            report.append((shown, "refused", str(error)))
            tell_refused(library, error)
            continue
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        if kind == "key":
            target = os.path.join(library, "keys", kid + ".json")
            if not os.path.exists(target):
                write_text(target, text)
            keys[kid] = vr.parse_public(body["key"])[1]
            report.append((shown, "filed", f"keys/{kid}.json"))
        elif kind == "dialin":
            target = f"dialins/{month_folder(body)}/{kid}-{digest}.json"
            write_text(os.path.join(library, target), text)
            report.append((shown, "filed", target))
        elif kind == "shot":
            target = f"shots/{month_folder(body)}/{kid}-{int(body['id'])}.json"
            write_text(os.path.join(library, target), text)
            report.append((shown, "filed", target))
        elif kind == "taste":
            target = f"tastes/{kid}-r{int(body['id'])}.json"
            write_text(os.path.join(library, target), text)
            report.append((shown, "filed", target))
        elif kind == "service_review":
            target = f"svcreviews/{kid}-v{int(body['id'])}.json"
            write_text(os.path.join(library, target), text)
            report.append((shown, "filed", target))
        elif kind == "service":   # a subscription service for the shared list: reviewed, like a machine
            local_id, record = body["local_id"], body["record"]
            pending = f"pending/services/{kid}/s{local_id}-{record}.json"
            if not set_status(library, kid, local_id, record, "review", section="services"):
                report.append((shown, "refused", "an earlier version of a service that has been sent again since"))
                continue
            write_text(os.path.join(library, pending), text)
            proposed = (slug(body["name"])[:39].strip("-")) or "unnamed"
            listed_path = f"services/{proposed}.json"
            exists = os.path.exists(os.path.join(library, listed_path))
            entry = {"id": proposed}
            entry.update({field: body[field] for field in SERVICE_FIELDS if field in body})
            plan.append({
                "branch": f"review/{kid}-s{local_id}-{record}",
                "title": f"{'Change' if exists else 'Add'} subscription service: {body['name']}",
                "body": service_request_text(library, kid, body, proposed, exists),
                "catalog_path": listed_path,
                "catalog_text": json.dumps(entry, indent=1) + "\n",
                "pending_path": pending,
            })
            report.append((shown, "for review", listed_path))
        elif kind == "grinder":   # a model for the shared list: reviewed, like a coffee
            local_id, record = body["local_id"], body["record"]
            pending = f"pending/grinders/{kid}/g{local_id}-{record}.json"
            if not set_status(library, kid, local_id, record, "review", section="grinders"):
                report.append((shown, "refused", "an earlier version of a grinder that has been sent again since"))
                continue
            write_text(os.path.join(library, pending), text)
            proposed = slug(body["model"]) or "unnamed"
            listed_path = f"grinders/{proposed}.json"
            exists = os.path.exists(os.path.join(library, listed_path))
            entry = {"id": proposed}
            entry.update({field: body[field] for field in GRINDER_FIELDS if field in body})
            plan.append({
                "branch": f"review/{kid}-g{local_id}-{record}",
                "title": f"{'Change' if exists else 'Add'} grinder: {body['model']}",
                "body": grinder_request_text(library, kid, body, proposed, exists),
                "catalog_path": listed_path,
                "catalog_text": json.dumps(entry, indent=1) + "\n",
                "pending_path": pending,
            })
            report.append((shown, "for review", listed_path))
        elif kind == "machine":   # a machine profile for the shared list: reviewed, like a grinder
            local_id, record = body["local_id"], body["record"]
            pending = f"pending/machines/{kid}/m{local_id}-{record}.json"
            if not set_status(library, kid, local_id, record, "review", section="machines"):
                report.append((shown, "refused", "an earlier version of a machine that has been sent again since"))
                continue
            write_text(os.path.join(library, pending), text)
            proposed = (slug(f"{body['maker']} {body['model']} {body['control']}")[:39].strip("-")) or "unnamed"
            listed_path = f"machines/{proposed}.json"
            exists = os.path.exists(os.path.join(library, listed_path))
            entry = {"id": proposed}
            entry.update({field: body[field] for field in MACHINE_FIELDS if field in body})
            plan.append({
                "branch": f"review/{kid}-m{local_id}-{record}",
                "title": f"{'Change' if exists else 'Add'} machine: {body['maker']} {body['model']} ({body['control']})",
                "body": machine_request_text(library, kid, body, proposed, exists),
                "catalog_path": listed_path,
                "catalog_text": json.dumps(entry, indent=1) + "\n",
                "pending_path": pending,
            })
            report.append((shown, "for review", listed_path))
        else:   # a coffee: never published from here
            local_id, record = body["local_id"], body["record"]
            pending = f"pending/coffees/{kid}/c{local_id}-{record}.json"
            if not set_status(library, kid, local_id, record, "review"):
                report.append((shown, "refused", "an earlier version of a coffee that has been sent again since"))
                continue
            write_text(os.path.join(library, pending), text)
            proposed = catalog_id(body)
            catalog_path = f"catalog/{proposed}.json"
            exists = os.path.exists(os.path.join(library, catalog_path))
            entry = {"id": proposed}
            entry.update({field: body[field] for field in CATALOG_FIELDS if field in body})
            plan.append({
                "branch": f"review/{kid}-c{local_id}-{record}",
                "title": f"{'Change' if exists else 'Add'} {body.get('roaster', 'unknown roaster')} / {body['name']}",
                "body": pull_request_text(library, kid, body, proposed, exists),
                "catalog_path": catalog_path,
                "catalog_text": json.dumps(entry, indent=1) + "\n",
                "pending_path": pending,
            })
            report.append((shown, "for review", catalog_path))
    for shown, outcome, detail in report:
        log(f"{outcome:<10} {shown}  {detail}")
    return plan, report


def summary_markdown(report):
    counts = {}
    for _, outcome, _ in report:
        counts[outcome] = counts.get(outcome, 0) + 1
    lines = ["## Intake", "",
             ", ".join(f"{n} {outcome}" for outcome, n in sorted(counts.items())) or "Nothing in the inbox.", ""]
    if report:
        lines += ["| File | Outcome | Detail |", "| --- | --- | --- |"]
        lines += [f"| `{shown}` | {outcome} | {detail.replace('|', '/')} |" for shown, outcome, detail in report]
    return "\n".join(lines) + "\n"


# ---- self-test ------------------------------------------------------------------
def self_test():
    import base64
    import tempfile
    import build_index as bi

    def person(private):
        point = vr._mul(private, vr.G)
        raw = b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        return private, vr.key_id(raw), base64.b64encode(raw).decode()

    anna, ben = person(0x1111), person(0x2222)
    coffee = {"t": "coffee", "v": 1, "at": "2026-10-10T22:51:50Z", "local_id": 4, "record": 7,
              "name": "Idjwi Island", "roaster": "Portrait Coffee", "origin": "DR Congo", "process": "washed",
              "roast_level": "medium-light", "altitude_m": 1900}
    dialin = {"t": "dialin", "v": 1, "at": "2026-10-10T23:00:00Z",
              "coffee": {"local_id": 4, "name": "Idjwi Island"},
              "recipe": {"dose_g": 18, "yield_g": 36, "target_time_s": 26},
              "grinder": {"model_id": 1, "unit": "um", "um_per_unit": 1, "calibration": 0},
              "grind": 246, "result": {"time_s": 25.6, "basis": "total", "shots": 3}}
    shot = {"t": "shot", "v": 1, "id": 60, "at": "2026-10-10T22:51:50Z",
            "recipe": {"dose_g": 18, "yield_g": 36}, "grinder": {"unit": "um", "calibration": 0},
            "grind": 246, "result": {"yield_g": 35.8, "time_s": 25.4, "end": "weight"}}

    with tempfile.TemporaryDirectory() as root:
        inbox, library = os.path.join(root, "inbox"), os.path.join(root, "library")
        os.makedirs(library)

        def drop(name, text):
            write_text(os.path.join(inbox, name), text)

        def env(who, body):
            return bi._envelope(who[0], who[1], body)

        # A good batch from Anna, in an order and under names that mean nothing.
        drop("zzz/1.json", env(anna, {"t": "key", "v": 1, "alg": "ES256", "key": anna[2]}))
        drop("a/whatever.json", env(anna, coffee))
        drop("a/../a/d.json", env(anna, dialin))
        drop("keys/pretend.json", env(anna, shot))
        drop("a/g.json", env(anna, {"t": "grinder", "v": 1, "record": 11, "local_id": 2,
                                     "model": "Home Built 64", "burrs": "64 mm flat", "unit": "dial"}))
        # And things that must not get in.
        drop("bad/tampered.json", env(anna, dialin).replace("246", "146"))
        drop("bad/wrong-type.json", env(anna, dict(dialin, grind="fine")))
        drop("bad/out-of-range.json", env(anna, dict(dialin, recipe={"dose_g": 180, "yield_g": 36})))
        drop("bad/no-key.json", env(ben, dialin))                       # Ben's key was never sent
        drop("bad/emulator.json", env(anna, dialin).replace('"alg":"ES256"', '"alg":"EMULATOR-UNSIGNED"'))
        drop("bad/not-json.json", "hello")
        drop("bad/huge.json", "x" * (MAX_RECORD_BYTES + 1))
        drop("bad/script.json", env(anna, dict(coffee, local_id=5, record=8, name="<script>alert(1)</script>" + "x" * 30)))
        # A machine Anna signed, refused for what it says (a style the controller does not offer).
        drop("bad/machine.json", env(anna, {"t": "machine", "v": 1, "record": 12, "local_id": 1, "maker": "Acme",
                                             "model": "One", "control": "lever", "style": "warp_drive"}))

        plan, report = take(inbox, library, log=lambda *_: None)
        outcome = {shown: (what, detail) for shown, what, detail in report}
        assert outcome["zzz/1.json"] == ("filed", f"keys/{anna[1]}.json")
        assert outcome["a/d.json"][0] == "filed" and outcome["a/d.json"][1].startswith(f"dialins/2026/10/{anna[1]}-")
        assert outcome["keys/pretend.json"] == ("filed", f"shots/2026/10/{anna[1]}-60.json")
        assert outcome["a/whatever.json"] == ("for review", "catalog/portrait-coffee/idjwi-island.json")
        for name, reason in (("tampered", "signature does not match"), ("wrong-type", "outside"),
                             ("out-of-range", "outside"), ("no-key", "not on file"), ("emulator", "not ES256"),
                             ("not-json", "not JSON"), ("huge", "too large"), ("script", "text of 1 to 23")):
            what, detail = outcome[f"bad/{name}.json"]
            assert what == "refused" and reason in detail, (name, detail)
        # Nothing was published: the catalog is untouched, the coffee is parked.
        assert not os.path.exists(os.path.join(library, "catalog"))
        assert os.path.exists(os.path.join(library, "pending", "coffees", anna[1], "c4-7.json"))
        assert not os.path.exists(os.path.join(library, "keys", ben[1] + ".json"))
        status = read_json(os.path.join(library, "status", anna[1] + ".json"))
        # Signed by her but refused for what they say: her controller is told why, line by line.
        refused_coffee = status["coffees"][1]
        assert status["coffees"][0] == {"local_id": 4, "record": 7, "state": "review"}
        assert refused_coffee["local_id"] == 5 and refused_coffee["record"] == 8 and refused_coffee["state"] == "refused"
        assert "text of 1 to 23" in refused_coffee["note"]
        assert status["machines"] == [{"local_id": 1, "record": 12, "state": "refused",
                                       "note": status["machines"][0]["note"]}] and status["machines"][0]["note"]
        assert outcome["bad/machine.json"][0] == "refused"
        # Records not signed by a key on file tell no one anything (tampered, unknown key, emulator...).
        assert ben[1] + ".json" not in os.listdir(os.path.join(library, "status"))
        assert status["grinders"] == [{"local_id": 2, "record": 11, "state": "review"}]
        assert outcome["a/g.json"] == ("for review", "grinders/home-built-64.json")
        gplan = [p for p in plan if p["branch"].endswith("-g2-11")][0]
        assert gplan["title"] == "Add grinder: Home Built 64" and '"kind":"grinder"' in gplan["body"]
        assert json.loads(gplan["catalog_text"]) == {"id": "home-built-64", "model": "Home Built 64", "burrs": "64 mm flat", "unit": "dial"}
        assert os.path.exists(os.path.join(library, "pending", "grinders", anna[1], "g2-11.json"))
        plan = [p for p in plan if p is not gplan]
        assert len(plan) == 1 and plan[0]["branch"] == f"review/{anna[1]}-c4-7"
        assert plan[0]["title"] == "Add Portrait Coffee / Idjwi Island"
        entry = json.loads(plan[0]["catalog_text"])
        assert entry["id"] == "portrait-coffee/idjwi-island" and entry["altitude_m"] == 1900 and "local_id" not in entry
        assert f'"kid":"{anna[1]}"' in plan[0]["body"] and "measurements on file" in plan[0]["body"]
        assert "| name | Idjwi Island |" in plan[0]["body"]

        # The same batch again changes nothing and files nothing twice.
        before = sorted(glob.glob(os.path.join(library, "**", "*.json"), recursive=True))
        take(inbox, library, log=lambda *_: None)
        assert before == sorted(glob.glob(os.path.join(library, "**", "*.json"), recursive=True))

        # The reviewer merges: published under the catalog's id.
        assert set_status(library, anna[1], 4, 7, "published", "portrait-coffee/idjwi-island")
        assert set_status(library, anna[1], 2, 11, "published", "home-built-64", section="grinders")
        both = read_json(os.path.join(library, "status", anna[1] + ".json"))
        assert both["coffees"][0]["state"] == "published" and both["grinders"][0]["library_id"] == "home-built-64"
        write_text(os.path.join(library, gplan["catalog_path"]), gplan["catalog_text"])
        write_text(os.path.join(library, plan[0]["catalog_path"]), plan[0]["catalog_text"])
        # A changed version arrives; a verdict on the old one comes too late to matter.
        write_text(os.path.join(root, "inbox2", "c.json"),
                   env(anna, dict(coffee, record=9, notes="plum")))
        plan2, _ = take(os.path.join(root, "inbox2"), library, log=lambda *_: None)
        assert plan2[0]["title"].startswith("Change ") and "this entry exists" in plan2[0]["body"]
        assert not set_status(library, anna[1], 4, 7, "declined", note="late")
        status = read_json(os.path.join(library, "status", anna[1] + ".json"))
        assert [e for e in status["coffees"] if e["local_id"] == 4] == [{"local_id": 4, "record": 9, "state": "review"}]
        assert set_status(library, anna[1], 4, 9, "declined",
                          note="Declined: already listed\tas Portrait / Idjwi Island, see the catalog entry")
        note = read_json(os.path.join(library, "status", anna[1] + ".json"))["coffees"][0]["note"]
        assert len(note) <= NOTE_LIMIT and "\t" not in note
        # With the status saying published, the index builder files her dial-in under the entry.
        set_status(library, anna[1], 4, 9, "published", "portrait-coffee/idjwi-island")
        bi.build(library, min_contributors=1, log=lambda *_: None)
        built = read_json(os.path.join(library, "index", "dialin", "portrait-coffee__idjwi-island.json"))
        assert built["recipes"][0]["fineness_um"] == 246.0
        assert read_json(os.path.join(library, "index", "coffees.json"))["coffees"][0]["id"] == "portrait-coffee/idjwi-island"
        assert read_json(os.path.join(library, "index", "grinders.json"))["grinders"] == [
            {"id": "home-built-64", "model": "Home Built 64", "burrs": "64 mm flat", "unit": "dial"}]
    assert slug("Café  Olé!") == "caf-ol" and catalog_id({"name": "X"}) == "unknown/x"
    long_id = catalog_id({"roaster": "Onyx Coffee Lab of Northwest Arkansas", "name": "Ethiopia Yirgacheffe Konga Natural"})
    assert len(long_id) <= CATALOG_ID_MAX and long_id.startswith("onyx-coffee-lab-of-n") and not long_id.endswith("-"), long_id

    # A subscription service goes to review; a review of a service is filed; a bad service is refused
    # and the owner told why.
    service = {"t": "service", "v": 1, "record": 41, "local_id": 3, "name": "Trade Coffee",
               "url": "https://www.drinktrade.com/", "manage_url": "https://www.drinktrade.com/account",
               "platform": "ordergroove", "kind": "coffee", "ships_to": ["US"], "cadences": [14, 28],
               "sourcing": ["fair_trade"]}
    with tempfile.TemporaryDirectory() as root:
        inbox, library = os.path.join(root, "inbox"), os.path.join(root, "library")
        os.makedirs(library)
        write_text(os.path.join(inbox, "k.json"), bi._envelope(anna[0], anna[1], {"t": "key", "v": 1, "alg": "ES256", "key": anna[2]}))
        write_text(os.path.join(inbox, "s.json"), bi._envelope(anna[0], anna[1], service))
        write_text(os.path.join(inbox, "r.json"), bi._envelope(anna[0], anna[1], {
            "t": "service_review", "v": 1, "id": 7, "service": "trade-coffee", "drinker": 1, "stars": 5,
            "aspects": {"value": 4}}))
        bad = dict(service, local_id=4, record=42, sourcing=["free_beer"])
        write_text(os.path.join(inbox, "bad.json"), bi._envelope(anna[0], anna[1], bad))
        plan, report = take(inbox, library, log=lambda *_: None)
        outcome = {name: (what, detail) for name, what, detail in report}
        assert outcome["s.json"] == ("for review", "services/trade-coffee.json")
        assert outcome["r.json"] == ("filed", f"svcreviews/{anna[1]}-v7.json")
        assert outcome["bad.json"][0] == "refused"
        splan = [p for p in plan if p["branch"] == f"review/{anna[1]}-s3-41"][0]
        assert splan["title"] == "Add subscription service: Trade Coffee" and "`fair_trade`" in splan["body"]
        assert json.loads(splan["catalog_text"])["id"] == "trade-coffee"
        assert "local_id" not in json.loads(splan["catalog_text"])
        status = read_json(os.path.join(library, "status", anna[1] + ".json"))
        assert {e["local_id"]: e["state"] for e in status["services"]} == {3: "review", 4: "refused"}
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--self-test", action="store_true")
    commands = parser.add_subparsers(dest="command")
    t = commands.add_parser("take")
    t.add_argument("--inbox", required=True)
    t.add_argument("--library", required=True)
    t.add_argument("--plan", help="where to write the pull requests to open, as JSON")
    t.add_argument("--summary", help="a Markdown file to append the report to")
    r = commands.add_parser("resolve")
    r.add_argument("--library", required=True)
    r.add_argument("--kid", required=True)
    r.add_argument("--local-id", type=int, required=True)
    r.add_argument("--record", type=int, required=True)
    r.add_argument("--state", choices=("published", "declined"), required=True)
    r.add_argument("--library-id", default="")
    r.add_argument("--note", default="")
    r.add_argument("--section", choices=("coffees", "grinders"), default="coffees")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.command == "take":
        plan, report = take(args.inbox, args.library)
        if args.plan:
            write_text(args.plan, json.dumps(plan, indent=1))
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as f:
                f.write(summary_markdown(report))
    elif args.command == "resolve":
        if not re.fullmatch(r"[0-9a-f]{20}", args.kid):
            parser.error("not a key id")
        note = re.sub(r"^\s*declined:\s*", "", args.note, flags=re.IGNORECASE)
        changed = set_status(args.library, args.kid, args.local_id, args.record, args.state,
                             args.library_id if args.state == "published" else "", note, args.section)
        print("status updated" if changed else "left alone: the contributor has sent a newer version")
    else:
        parser.error("give a command, or --self-test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
