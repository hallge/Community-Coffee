# Community Coffee

The shared coffee library for Brew by Weight controllers: coffees, and what
people's grinders settled at for each of them. Controllers send signed
records here; nothing a controller sends is published until it has been
checked, and no coffee is published until a person has reviewed it.

## How a record gets in

```
controller     signs a record, pushes it to the inbox branch (inbox/...)
inbox branch   its one small workflow asks main to come and look
main: Intake   checks every record:
                 1. the envelope is well formed
                 2. the signature matches the body, with a key on file
                 3. every value has the expected type and is in range
               passes, and is a ...
                 key       -> keys/
                 dial-in   -> dialins/        measurements: checked, not reviewed
                 shot      -> shots/
                 coffee    -> pending/, and a pull request that would add it
                              to catalog/. The contributor's status file
                              says "review".
                 grinder   -> the same, for grinders/: a model its owner
                              typed in, offered for the shared list
               fails -> left out, listed with the reason in the run's summary
               then: index rebuilt, inbox emptied
reviewer       merges the pull request (publish) or closes it (decline)
main: Review   status file says "published" (and under what id) or
outcome        "declined" (with the reviewer's note); index rebuilt
controller     reads status/<its key id>.json and index/ and shows its owner
```

Records are **signed, not encrypted**. Anyone who can read this repository
can read a record; what the signature gives is that a record cannot be
altered or forged in another controller's name, and that everything from one
controller can be recognised as such. It does not prove the sender is a real
controller, since the firmware is open. That is what the review is for.

## Reviewing a coffee

Each pull request titled "Add roaster / coffee" shows the fields, who sent it
(a key id, and how much else is on file from that controller) and any similar
entries already in the catalog.

- **Publish:** merge. Edit the catalog file in the pull request first if a
  name or detail needs tidying; the entry's `id` is what it is published as.
- **Decline:** close it. If the last comment starts with `Declined:`, the
  rest of that line (47 characters) is shown to the contributor.

## Reviewing a grinder

A pull request titled "Add grinder: model" proposes a grinder model for the
shared list, so that the next owner of one picks it instead of typing it,
and settings can be compared among everyone who has it. Check the name, and
what a setting is read in (`unit`). Keep `um_per_unit` (microns of burr gap
per unit) only if the maker publishes it; left out, the index works the
scale out from shared shots. Merge to list it, close to decline, as for a
coffee.

## Folders

| Folder | What | Written by |
| --- | --- | --- |
| `catalog/<roaster>/<coffee>.json` | Published coffees | Reviewers, by merging |
| `grinders/<model>.json` | Grinder models reviewers have listed | Reviewers, by merging |
| `keys/<key id>.json` | Contributors' public keys | Intake |
| `dialins/<yyyy>/<mm>/` | Settled dial-ins | Intake |
| `shots/<yyyy>/<mm>/` | Shots, where an owner shares them | Intake |
| `pending/coffees/<key id>/`, `pending/grinders/<key id>/` | Coffees and grinders waiting for review | Intake |
| `status/<key id>.json` | Where each contributor's coffees and grinders stand | Intake, Review outcome |
| `index/` | What controllers read: coffee list, grinder list, community figures, grinder fits, and how fast the grind follows a coffee's age (`age.json`) | Built, never edited |
| `tools/` | The checks and builders the workflows run | By hand |

## The tools

Python 3.8 or later, nothing to install. Each has a `--self-test`.

| Tool | Does |
| --- | --- |
| `tools/verify_record.py` | Checks one record: envelope, key, ECDSA P-256 signature, types and ranges |
| `tools/intake.py` | Runs that over the inbox, files what passes, plans the review pull requests |
| `tools/reviews.py` | Opens those pull requests; records a reviewer's decision |
| `tools/build_index.py` | Builds `index/`, including how settings translate between grinders |

```bash
python tools/intake.py --self-test
```

## Setting up (once)

1. Settings, Actions, General, Workflow permissions: **Read and write**, and
   tick **Allow GitHub Actions to create and approve pull requests**.
   Without this the Intake cannot open the review pull requests.
2. The `inbox` branch must exist, holding `.github/workflows/poke.yml` and an
   `inbox/` folder.
3. Each controller needs a fine-grained token for this repository only, with
   **Contents: read and write** and nothing else. Such a token cannot change
   workflow files, so it cannot change what the checks do.
4. While the repository is private, controllers need that token to read
   `index/` and `status/` as well. Made public, reading needs no token.

## Record format

```json
{"v":1,"kid":"<key id>","alg":"ES256","sig":"<base64 r|s>","body":"{...}"}
```

`body` is the record as a string, exactly as it was signed. `kid` is the
first 20 hex digits of the SHA-256 of the public key (65 bytes,
uncompressed). The PC emulator has no real key: it signs with
`EMULATOR-UNSIGNED`, which is refused.

What the library tells a controller, `status/<key id>.json`:

```json
{"v":1,"coffees":[
  {"local_id":1,"record":2,"state":"published","library_id":"portrait/idjwi-island"},
  {"local_id":3,"record":5,"state":"declined","note":"Already listed as Colombia Huila Decaf"}
]}
```

`record` is the number the controller gave that version of the coffee (it is
inside the signed record). A verdict only counts for the version last sent.
A `grinders` list in the same file does the same for grinders a contributor
has sent.
