# capper-runner (public, sealed)

This repo runs the proprietary CapperSuite pipeline on **free GitHub-hosted
runners**. It contains **no source code**: only these workflows and
`bundles/pipeline.seal`, an encrypted tarball of the pipeline. The X25519
decryption key lives exclusively in Actions secrets and is used only inside
ephemeral runners.

Why: standard runners are free for public repositories (GitHub docs — "Runner
usage in public repositories will remain free"), while the code is
proprietary. Sealing gets both. See `docs/implementation_plan_2026-10.md` in
the private repo for the full design and threat model.

## Threat model (read before changing workflows)

- Protected: the public, forks, clone-scrapers — they see ciphertext + YAML.
- NOT protected: GitHub itself, or anyone holding `PIPELINE_SEAL_KEY`.
- The attack surface is these workflow files. Rules:
  - branch protection: only the owner may push; CODEOWNERS on `.github/**`
  - never use `pull_request_target`, never check out untrusted code
  - never `echo` secrets; `GITHUB_TOKEN` stays read-only
  - fork pull requests must not run jobs that see secrets
- The key needs an OFFLINE BACKUP. Lost key = undecryptable bundle = the
  pipeline cannot run anywhere until the private repo re-seals with a new key.

## Setup (once)

1. `git init`, push this scaffold as a PUBLIC repo.
2. Add Actions secrets: `PIPELINE_SEAL_KEY` (private half from
   `scripts/seal_and_ship.py keygen`) plus every pipeline secret the
   workflows reference (Discord, Supabase, Gemini, web-evidence, Twitter,
   Telegram — same list as the private repo's workflows).
3. Settings → Actions → allow actions, restrict to local actions if you want
   extra paranoia; disable fork-PR runs with secrets (default is already safe:
   fork PRs never receive secrets).
4. Enable branch protection on `main`.

## Ship flow (from the private repo)

```
.venv/bin/python scripts/seal_and_ship.py bundle --out /tmp/pipeline.tgz
.venv/bin/python scripts/seal_and_ship.py seal  --in /tmp/pipeline.tgz \
    --out /tmp/pipeline.seal --recipient <RECIPIENT_PUB>
.venv/bin/python scripts/seal_and_ship.py verify --in /tmp/pipeline.seal   # needs the key
.venv/bin/python scripts/seal_and_ship.py ship  --in /tmp/pipeline.seal --repo-dir ../capper-runner
```

Then commit + push this repo yourself. Shipping is never automatic: every
bundle that reaches a public repo passes through a human.

`bundles/SHA256` pins the committed blob; workflows verify before decrypting
so a corrupted or swapped blob fails loudly instead of running garbage.
