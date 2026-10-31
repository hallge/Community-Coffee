#!/usr/bin/env python3
"""The two ends of a coffee's review, as run by the workflows.

    python tools/reviews.py open <plan.json>      after intake: one pull request per coffee
    python tools/reviews.py close                 when such a pull request is merged or closed
    python tools/reviews.py --self-test

`open` runs in a checkout of main and uses git and the GitHub CLI (GH_TOKEN).
`close` reads the pull request from the environment (PR_NUMBER, PR_MERGED,
PR_BODY) and from the GitHub CLI, then writes the reviewer's decision into
the contributor's status file: published, under the id of the catalog file
that was merged, or declined, with the reviewer's note.

Nothing from a pull request or a record is ever run or pasted into a
command: it is only read as text.
"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_index  # noqa: E402
import intake  # noqa: E402


def run(*command, check=True, capture=False):
    result = subprocess.run(command, check=check, text=True, capture_output=capture)
    return result.stdout if capture else result.returncode


# A review branch Intake names: review/<key id>-<c|g|m|s><local id>-<record> (coffee, grinder, machine,
# subscription service).
REVIEW_BRANCH = r"review/[0-9a-f]{20}-[cgmsr]\d+-\d+"


def open_reviews(plan_path):
    plan = intake.read_json(plan_path, []) or []
    opened = 0
    for item in plan:
        if item.get("op") == "owner_review":
            owner_review(item)
            continue
        branch = item["branch"]
        if not re.fullmatch(REVIEW_BRANCH, branch):
            print(f"skipped: not a review branch name: {branch!r}")
            continue
        if run("git", "ls-remote", "--exit-code", "--heads", "origin", branch, check=False, capture=True):
            print(f"already open: {branch}")
            continue
        run("git", "switch", "--quiet", "-c", branch, "origin/main")
        intake.write_text(item["catalog_path"], item["catalog_text"])
        run("git", "add", "--", item["catalog_path"])
        if os.path.exists(item["pending_path"]):
            run("git", "rm", "--quiet", "--", item["pending_path"])
        run("git", "commit", "--quiet", "-m", item["title"])
        run("git", "push", "--quiet", "origin", branch)
        body_file = os.path.join(os.environ.get("RUNNER_TEMP", "."), "pr-body.md")
        intake.write_text(body_file, item["body"])
        run("gh", "pr", "create", "--base", "main", "--head", branch, "--title", item["title"],
            "--body-file", body_file)
        run("git", "switch", "--quiet", "--detach", "origin/main")
        opened += 1
    print(f"{opened} pull request(s) opened")


def owner_review_comment(item):
    """The comment an owner review leaves on the item's pull request. Never a key in full: its start."""
    who = f"an owner (key `{item['reviewer'][:6]}…`)"
    if item["verdict"] == "approve":
        text = f"Approved by {who}: {item['approvals']} of {intake.OWNER_APPROVALS} approvals."
    else:
        text = f"Declined by {who}: {item['note'] or 'no reason given'}. Held for a person to decide."
    if item.get("publish"):
        text += " Enough approvals and no decline: merging to publish."
    return text


def owner_review(item):
    """An owner review from intake's plan: a comment on the item's pull request; a decline labels it and
    leaves it open; enough approvals merge it and write the published status, as close does (a merge
    made with the workflow's token starts no workflow, so review-outcome would not run)."""
    branch = item["branch"]
    if not re.fullmatch(REVIEW_BRANCH, branch):
        print(f"skipped: not a review branch name: {branch!r}")
        return
    if run("gh", "pr", "view", branch, "--json", "number", check=False, capture=True) == "":
        print(f"no pull request for {branch}: review kept for when it opens")
        return
    body_file = os.path.join(os.environ.get("RUNNER_TEMP", "."), "owner-review.md")
    intake.write_text(body_file, owner_review_comment(item))
    run("gh", "pr", "comment", branch, "--body-file", body_file)
    if item["verdict"] == "decline":
        run("gh", "label", "create", "owner-declined", "--color", "B60205", "--force", check=False)
        run("gh", "pr", "edit", branch, "--add-label", "owner-declined", check=False)
        return
    if not item.get("publish"):
        return
    view = json.loads(run("gh", "pr", "view", branch, "--json", "number,body,labels", capture=True))
    if any(l.get("name") == "owner-declined" for l in view.get("labels", [])):
        print(f"{branch}: declined before, left for a person")
        return
    run("gh", "pr", "merge", branch, "--merge", "--delete-branch")
    run("git", "fetch", "--quiet", "origin", "main")
    run("git", "switch", "--quiet", "--detach", "origin/main")
    close_review(str(view["number"]), True, view.get("body", ""))
    if os.path.exists(intake.reviews_path(item["target"])):
        os.remove(intake.reviews_path(item["target"]))
    run("git", "add", "-A", "--", "status", "pending")
    if run("git", "diff", "--cached", "--quiet", check=False) != 0:
        run("git", "commit", "--quiet", "-m", f"Published by owner review: {item['target']}")
        run("git", "push", "--quiet", "origin", "HEAD:main")


def decision(body, merged, comments, files, read_catalog):
    """What to write in the status file, from a closed review pull request.

    body: the pull request's text. comments: its comments' texts, oldest first.
    files: paths it changed. read_catalog(path) -> the catalog entry, or None.
    Returns None if this is not a review pull request.
    """
    match = re.search(r"<!-- intake (\{.*?\}) -->", body or "")
    if not match:
        return None
    try:
        meta = json.loads(match.group(1))
        kid, local_id, record = meta["kid"], int(meta["local_id"]), int(meta["record"])
    except (ValueError, KeyError, TypeError):
        return None
    if not re.fullmatch(r"[0-9a-f]{20}", str(kid)):
        return None
    kind = meta.get("kind") if meta.get("kind") in ("grinder", "machine", "service", "link", "recipe") else "coffee"
    folder = {"grinder": "grinders/", "machine": "machines/", "service": "services/",
              "link": "links/", "recipe": "recipes/"}.get(kind, "catalog/")
    result = {"kind": kind, "kid": kid, "local_id": local_id, "record": record}
    if merged:
        # The reviewer may have renamed the entry: go by what was merged.
        library_id = ""
        for path in files:
            if path.startswith(folder) and path.endswith(".json"):
                entry = read_catalog(path)
                if isinstance(entry, dict) and build_index.library_file(entry.get("id")):
                    library_id = entry["id"]
        if not library_id:
            return None     # merged without a catalog entry: nothing was published
        result.update(state="published", library_id=library_id, note="")
    else:
        note = ""
        for text in reversed(comments or []):
            found = re.match(r"\s*declined:\s*(.+)", text or "", flags=re.IGNORECASE)
            if found:
                note = found.group(1).splitlines()[0]
                break
        result.update(state="declined", library_id="", note=note or "Not accepted by a reviewer")
    return result


def close_review(number=None, merged=None, body=None):
    number = number or os.environ["PR_NUMBER"]
    if merged is None:
        merged = os.environ.get("PR_MERGED", "").lower() == "true"
    if body is None:
        body = os.environ.get("PR_BODY", "")
    view = json.loads(run("gh", "pr", "view", number, "--json", "comments,files", capture=True))
    comments = [c.get("body", "") for c in view.get("comments", [])]
    files = [f.get("path", "") for f in view.get("files", [])]
    result = decision(body, merged, comments, files, intake.read_json)
    if result is None:
        print("not a review pull request, or nothing was published: status left alone")
        return
    section, letter = {"grinder": ("grinders", "g"), "machine": ("machines", "m"), "service": ("services", "s"),
                       "link": ("links", "l"), "recipe": ("recipes", "r")}.get(result["kind"], ("coffees", "c"))
    changed = intake.set_status(".", result["kid"], result["local_id"], result["record"],
                                result["state"], result["library_id"], result["note"], section)
    pending = f"pending/{section}/{result['kid']}/{letter}{result['local_id']}-{result['record']}.json"
    if os.path.exists(pending):
        os.remove(pending)   # decided either way: no longer waiting
    print(f"{result['state']}: key {result['kid']} {result['kind']} {result['local_id']} record {result['record']}"
          + ("" if changed else " (a newer version has been sent since: status left alone)"))


def self_test():
    body = 'text\n<!-- intake {"kid":"0123456789abcdef0123","local_id":4,"record":7,"library_id":"a/b"} -->'
    catalog = {"catalog/portrait/idjwi-island.json": {"id": "portrait/idjwi-island", "name": "Idjwi Island"}}
    merged = decision(body, True, [], ["catalog/portrait/idjwi-island.json", "pending/x.json"], catalog.get)
    assert merged == {"kind": "coffee", "kid": "0123456789abcdef0123", "local_id": 4, "record": 7, "state": "published",
                      "library_id": "portrait/idjwi-island", "note": ""}       # the merged file's id, not the proposal's
    assert decision(body, True, [], ["README.md"], catalog.get) is None
    closed = decision(body, False, ["looks odd", "Declined: already listed as portrait/idjwi\nmore", "ok"],
                      [], catalog.get)
    assert closed["state"] == "declined" and closed["note"] == "already listed as portrait/idjwi"
    assert decision(body, False, [], [], catalog.get)["note"] == "Not accepted by a reviewer"
    assert decision("an ordinary pull request", True, [], [], catalog.get) is None
    gbody = '<!-- intake {"kind":"grinder","kid":"0123456789abcdef0123","local_id":2,"record":11} -->'
    listed = {"grinders/home-built-64.json": {"id": "home-built-64", "model": "Home Built 64", "unit": "dial"}}
    g = decision(gbody, True, [], ["grinders/home-built-64.json"], listed.get)
    assert g["kind"] == "grinder" and g["library_id"] == "home-built-64" and g["state"] == "published"
    # A machine profile is reviewed the same way.
    assert all(re.fullmatch(REVIEW_BRANCH, f"review/0123456789abcdef0123-{k}1-12") for k in "cgmr")
    # A recipe merged: published under the recipe book's file.
    rbody = 'x\n<!-- intake {"kind":"recipe","kid":"0123456789abcdef0123","local_id":3,"record":30,"library_id":"turbo-shot"} -->'
    rmerged = decision(rbody, True, [], ["recipes/turbo-shot.json"], {"recipes/turbo-shot.json": {"id": "turbo-shot"}}.get)
    assert rmerged["kind"] == "recipe" and rmerged["state"] == "published" and rmerged["library_id"] == "turbo-shot"
    # What an owner review says on the pull request: never the key in full.
    item = {"verdict": "approve", "reviewer": "0123456789abcdef0123", "approvals": 2, "publish": True, "note": ""}
    text = owner_review_comment(item)
    assert "2 of 2" in text and "merging" in text and "0123456789abcdef0123" not in text
    assert "Held" in owner_review_comment(dict(item, verdict="decline", note="No", publish=False))
    assert not re.fullmatch(REVIEW_BRANCH, "review/0123456789abcdef0123-x1-12")
    mbody = '<!-- intake {"kind":"machine","kid":"0123456789abcdef0123","local_id":1,"record":12} -->'
    mlisted = {"machines/breville-dual-boiler-2-cup-button.json": {"id": "breville-dual-boiler-2-cup-button"}}
    m = decision(mbody, True, [], ["machines/breville-dual-boiler-2-cup-button.json"], mlisted.get)
    assert m["kind"] == "machine" and m["library_id"] == "breville-dual-boiler-2-cup-button" and m["state"] == "published"
    m = decision(mbody, False, ["declined: the 2 CUP button is volumetric"], [], mlisted.get)
    assert m["kind"] == "machine" and m["state"] == "declined" and m["note"] == "the 2 CUP button is volumetric"
    # A subscription service too.
    sbody = '<!-- intake {"kind":"service","kid":"0123456789abcdef0123","local_id":3,"record":41} -->'
    slisted = {"services/trade-coffee.json": {"id": "trade-coffee", "name": "Trade Coffee"}}
    sv = decision(sbody, True, [], ["services/trade-coffee.json"], slisted.get)
    assert sv["kind"] == "service" and sv["library_id"] == "trade-coffee" and sv["state"] == "published"
    assert re.fullmatch(REVIEW_BRANCH, "review/0123456789abcdef0123-s3-41")
    assert decision(gbody, True, [], ["catalog/portrait/idjwi-island.json"], catalog.get) is None   # wrong folder
    assert decision(body.replace("0123456789abcdef0123", "../../etc"), True, [], [], catalog.get) is None
    assert decision('<!-- intake {"kid":1} -->', False, [], [], catalog.get) is None
    bad = {'catalog/x.json': {'id': '../../etc/passwd'}}
    assert decision(body, True, [], ['catalog/x.json'], bad.get) is None     # not an id the library uses
    print("self-test passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    elif len(sys.argv) == 3 and sys.argv[1] == "open":
        open_reviews(sys.argv[2])
    elif sys.argv[1:] == ["close"]:
        close_review()
    else:
        sys.exit(__doc__)
