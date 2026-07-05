# Contributing to this Wiki

This wiki is **version-controlled in the main repo**, not edited on the web. The Markdown lives in
[`wiki/`](https://github.com/0x13d/attack/tree/main/wiki); a GitHub Action mirrors it to the wiki on every push
to `main`.

## Editing

1. Edit the `.md` files under `wiki/` in the main repo (through a normal PR).
2. On merge to `main`, `.github/workflows/publish-wiki.yml` pushes the folder to the wiki — no manual web edits.

Page names map to filenames (`Rule-Reference.md` → **Rule Reference**). `_Sidebar.md` is the nav.

## Why not edit on the web?

A GitHub wiki is itself a git repo (`github.com/0x13d/attack.wiki.git`), but web edits bypass review and drift
from the code. Keeping the source in `wiki/` gives it the same PR review, history, and CI as everything else —
one source of truth.

## First-time setup (once per repo)

The wiki repo only exists after the wiki is enabled **and** has one initial page:

1. Repo **Settings → Features → Wikis**: on.
2. Create any page once via the web UI (this initializes `…​.wiki.git`).
3. After that, the publish workflow keeps it in sync from `wiki/`.
