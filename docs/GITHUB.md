# GitHub setup of tavrn-js

The repository is prepared so that nothing runs on GitHub until the owner switches it on. This page lists what is
configured in the repository and what has to be set by hand.

## Workflows

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` → `JavaScript` | push to `main`, pull requests, by hand | the organization's `js-ci.yml`: install from the lockfile (with the private protocol submodule and the `@tavrn/crypto` git dependency), generated SDK types up to date (`scripts/check-generated.sh`), SPDX headers, dependency licenses, typecheck, Vitest in all three packages (bot unit tests only), `pnpm pack --dry-run` of the three packages |
| `ci.yml` → `Publication hygiene` | same | `scripts/publish-check.sh`: no private files, domains or secrets |
| `ci.yml` → `Bot integration tests (real nodes)` | push to `main`, by hand (never pull requests) | on the self-hosted runner `tavrn-e2e`: copies `tavrn-node` out of the node image and runs `@tavrn/bot`'s tests including `bot/test/node/` (`TAVRN_NODE_BIN`); additionally gated by `BOT_NODE_TESTS` |
| `release.yml` | tag `v*.*.*` | checks that the tag equals the version of all three packages, runs the checks, packs the three npm tarballs and attaches them to a GitHub release; publishes to npm with provenance only with `PUBLISH_ENABLED` (and refuses git dependencies) |
| `gitleaks.yml` | push to `main`, pull requests, by hand | the organization's `gitleaks.yml`: secret scan of the full history (`.gitleaks.toml`) |
| `dependency-review.yml` | pull requests | refuses vulnerable dependencies and licenses outside the allow-list |
| `cla.yml` | pull requests, comments | the organization's `cla.yml` (CLA bot) |

The reusable workflows live in [`just-tavrn/.github`](https://github.com/just-tavrn/.github); its `docs/GITHUB.md`
describes the organization settings and how to create the tokens below.

Every job carries `if: ${{ vars.CI_ENABLED == 'true' }}`.

## Variables and secrets (Settings → Secrets and variables → Actions)

| Name | Kind | Purpose |
|---|---|---|
| `CI_ENABLED` | variable | `true` switches all workflows on. Unset or anything else: every job is skipped. |
| `BOT_NODE_TESTS` | variable | `true` also runs the bot integration job on the self-hosted runner. Leave unset until the node image exists and the runner may serve this repository (below). |
| `TAVRN_NODE_IMAGE` | variable | optional: the node image for the bot integration job (default `ghcr.io/just-tavrn/tavrn-node:edge`; a manual run can pass another one). |
| `TAVRN_READ_PAT` | secret | Private phase only: fine-grained PAT with `contents: read` on `tavrn-protocol`, `tavrn-crypto` and `tavrn-js`, passed to the reusable workflow as `READ_TOKEN` so it can fetch the `protocol/` submodule and the `@tavrn/crypto` git dependency. Delete it once the repositories are public. |
| `PUBLISH_CHECK_PRIVATE` | secret (repository or organization) | comma-separated private domains, hosts and addresses that must never appear in the tree (`Publication hygiene`). Without it the check fails on purpose. Locally the same list lives in an untracked `.publish-check.private` (in the repository or its parent directory). |
| Dependabot secrets | secret (Dependabot) | Dependabot pull requests run with Dependabot's own secret store: add `TAVRN_READ_PAT` and `PUBLISH_CHECK_PRIVATE` again under Settings → Secrets and variables → Dependabot (or as organization Dependabot secrets), otherwise their CI fails at the private git dependencies and at the hygiene check. |
| `PUBLISH_ENABLED` | variable | `true` lets the release workflow publish to npm (after the GitHub release). Leave unset until the repositories are public and the git dependencies have become version ranges. |
| `NPM_TOKEN` | secret | npm automation token with publish rights for the `@tavrn` scope (only with `PUBLISH_ENABLED`). |
| `CLA_PAT` | organization secret | the CLA bot's token (`contents: write` on `just-tavrn/cla-signatures`). Organization secrets do not reach private repositories on the free plan: until the repository is public, add it as a repository secret as well. |

## Bot integration tests on the self-hosted runner

`bot/test/node/` starts real `tavrn-node --dev` processes. Locally: `TAVRN_NODE_BIN=/path/to/tavrn-node just test-node`.
In the CI the job `Bot integration tests (real nodes)` runs on the test host's runner (label `tavrn-e2e`, set up as
described in the organization's `docs/GITHUB.md`) and takes the binary from the node image. Before setting
`BOT_NODE_TESTS=true`:

- the runner group `tavrn-e2e` must include `tavrn-js` (Organization settings → Actions → Runner groups; it was created
  for `tavrn-web` only),
- the image `ghcr.io/just-tavrn/tavrn-node` must exist and grant `tavrn-js` read access (package settings → "Manage
  Actions access"), since the job pulls it with the job token.

The job never runs for pull requests: a self-hosted runner executes the code it checks out.

## Releases (private phase)

1. Bump `version` in `sdk/package.json`, `e2ee/package.json` and `bot/package.json` (and `SDK_VERSION` in
   `sdk/src/index.ts`, `BOT_VERSION` in `bot/src/bot.ts`) to the same `X.Y.Z`; if the protocol moved, bump the
   `protocol` submodule to its tag, run `just generate` and commit `sdk/src/generated`.
2. `just check`, commit, tag `vX.Y.Z`, push the tag.
3. With `CI_ENABLED` the release workflow attaches the three tarballs to a GitHub release. `v0.1.0` was tagged before
   the CI ran, without a GitHub release.

Consumers (`tavrn-web`, bots) reference the tag: `github:just-tavrn/tavrn-js#vX.Y.Z&path:sdk` (and `&path:e2ee`,
`&path:bot`, with the `overrides` from the README). When the packages are published to npm, `@tavrn/crypto`
becomes a version range here, consumers switch to version ranges, and `PUBLISH_ENABLED` is set.

## Settings applied through the API

Default branch `main`, delete branches on merge, squash merges allowed, issues on, wiki off, projects off. Labels
from `scripts/github-labels.sh` (idempotent; rerun it after editing the list).

## Settings the owner flips by hand

- [ ] `CI_ENABLED` and the secrets above when CI should run.
- [ ] Secret scanning with push protection (Settings → Code security; free for public repositories).
- [ ] Private vulnerability reporting (Settings → Code security), so "Report a vulnerability" works.
- [ ] Dependency graph and Dependabot alerts (needed by `dependency-review.yml`; on private repositories only with
      GitHub Advanced Security). Dependabot version updates run as soon as `dependabot.yml` exists (not gated by
      `CI_ENABLED`); pause them under Insights → Dependency graph → Dependabot to keep the private phase quiet.
- [ ] Actions access: while `just-tavrn/.github` is private, its Settings → Actions → General → Access must be
      "Accessible from repositories in the just-tavrn organization", or every push shows a failed run with
      "workflow file issue".
- [ ] Discussions: questions are routed to the Discussions of the umbrella repository `just-tavrn/tavrn`
      (`ISSUE_TEMPLATE/config.yml`); nothing to switch on here.
- [ ] Team `@just-tavrn/maintainers` must exist for `CODEOWNERS`.
- [ ] Once public: branch protection or a ruleset for `main` (require pull requests with one review from
      `@just-tavrn/maintainers`, the checks `JavaScript`, `Publication hygiene`, `gitleaks`, `Dependency review`,
      `CLA`, linear history, no force pushes, no deletions) and tag protection for `v*`. Not available for private
      repositories on the free plan.
