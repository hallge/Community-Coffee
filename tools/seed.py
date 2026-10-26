"""Seed entries for the shared library: grinder models the firmware knows, as published entries.

    python tools/seed.py write-grinders <firmware repo>/src/core/GrinderRegistry.h seed/grinders
        (re)writes seed/grinders/<id>.json from the firmware's built-in list, so the two agree.

    python tools/seed.py install <library checkout>
        copies seed/grinders/*.json into the library's grinders/ folder where no entry of that id
        is there yet (a published entry, perhaps corrected by a reviewer since, is never overwritten),
        and says what it added. Commit and push those, and the next index build lists them.

A seeded entry is an ordinary published grinder: owners propose corrections through the usual
review (their own version, sent; a reviewer merges it into the entry).
"""

import glob
import json
import os
import re
import shutil
import sys

# Where a figure comes from, kept beside it for the reviewer who checks a correction.
SOURCES = {
    "mahlkonig-e64-ws": "The grinder's display reads the burr gap in microns.",
    "1zpresso-j-max": "1Zpresso: 8.8 microns per click.",
    "1zpresso-k-ultra": "1Zpresso: 20 microns per click.",
    "comandante-c40": "Comandante: about 30 microns per click (MK3/MK4).",
    "baratza-sette-270": "Macro 1-31, micro A-I (9 steps each), read as macro:micro.",
    "baratza-vario": "Macro 1-10, micro A-W (23 steps each), read as macro:micro.",
}

ENTRY = re.compile(r'\{(\d+), "([^"]+)", "([^"]+)", "([^"]+)", ([0-9.]+)f, (\d+), (\d+), (\d+), (\d+),\s*"([^"]+)"\}')


def write_grinders(registry, out):
    text = open(registry, encoding="utf-8").read()
    os.makedirs(out, exist_ok=True)
    count = 0
    for m in ENTRY.finditer(text):
        model_id, model, burrs, unit, um, divisor, sub, lo, hi, library_id = m.groups()
        entry = {"id": library_id, "model": model, "burrs": burrs, "unit": unit, "model_id": int(model_id)}
        if float(um) > 0:
            entry["um_per_unit"] = float(um)
        if int(divisor) > 1:
            entry["divisor"] = int(divisor)
        if int(sub) >= 2:
            entry["sub_steps"] = int(sub)
        if int(hi):
            entry["min"], entry["max"] = int(lo), int(hi)
        entry["source"] = SOURCES.get(library_id, "Steps as marked on the grinder; microns per step not "
                                                  "published: learned from owners' shots.")
        with open(os.path.join(out, library_id + ".json"), "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=1, ensure_ascii=False)
            f.write("\n")
        count += 1
    print(f"{count} grinder entries written to {out}")
    return count


def install(library):
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "seed", "grinders")
    target = os.path.join(library, "grinders")
    os.makedirs(target, exist_ok=True)
    added = []
    for path in sorted(glob.glob(os.path.join(here, "*.json"))):
        dest = os.path.join(target, os.path.basename(path))
        if not os.path.exists(dest):
            shutil.copyfile(path, dest)
            added.append(os.path.basename(path))
    print(f"{len(added)} added to {target}" + ("".join(f"\n  {a}" for a in added) if added else ""))
    return added


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "write-grinders":
        write_grinders(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "install":
        install(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)
