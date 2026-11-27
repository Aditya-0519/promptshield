# PromptShield 0.2.1 release package

This directory is a clean repository-root release package. It intentionally does not include a `.git` directory or local target configurations.

## If integrating into an existing local clone

1. Back up your current project first.
2. Preserve your existing `.git` directory. Do not copy a `.git` directory from an archive.
3. Replace/add the source, tests, docs, attacks, examples, and workflow files from this release.
4. Keep your private target configs outside the public repository, or recreate them from `promptshield.config.example.json` with environment-variable references.
5. Run `npm test` and `npm run check`.
6. Inspect `git status` and the diff before committing. Do not commit `.env`, API keys, private canaries, unredacted reports, or target data.

## Security behavior change

HTTP redirects are rejected. If your API intentionally redirects, configure the final authorized endpoint directly. The authorization opt-in applies to both `url` and `startUrl`.

## Current release limitations

Agent/tool-call authorization testing, browser-based login flows, adaptive attacker-model testing, and a published false-positive/false-negative benchmark are not included. Provider compatibility has mock-server tests; live provider testing remains an operator responsibility.
