# Inbox

Controllers push their signed records here, under `inbox/`. Nothing on this
branch is trusted or published. The Intake workflow on `main` checks every
record (signature, types, ranges), files the good ones on `main`, opens a
pull request for each coffee, and then empties this folder.
