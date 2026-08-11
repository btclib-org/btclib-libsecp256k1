# Repository configuration

Read this before changing a workflow, a branch rule or a repository
setting; writing code does not need it. [CLAUDE.md](CLAUDE.md) points here
rather than carrying it, so that a session fixing a wrapper does not hold
it in context.

The branch rules and the repository settings live *outside* the
repository, so this file is the whole of them: nothing here can be
recovered by reading the tree. Every value below was read from the API,
and the command that reads it is beside it.

## Required checks on main

**Never name matrix contexts in a branch rule.** The rule lives outside
the repository, so a context that stops being produced blocks every merge
with nothing in the tree to explain why — and the matrix here is
`Run the suite on the static wheel, ${{ matrix.python-version }},
${{ matrix.os }}`, whose contexts change with every interpreter added or
dropped. `test: every job passed` is the aggregate job at the end of
`test.yml` that `needs` every other job in it; a job added to that
workflow belongs in its `needs` list, or it gates nothing. The name
carries the workflow because a context is keyed by name alone: two
workflows with a job named the same thing produce one ambiguous check.

What the rule holds is read from the endpoint, never assumed:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/branches/main/protection \
  --jq '.required_status_checks'
```

| Check | Produced by |
| --- | --- |
| `test: every job passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, its only job |
| `Build the documentation` | `docs.yml`, its only job |
| `CodeQL` | code scanning's default setup |

`Build the documentation` is named on its own on purpose: a rule naming
`Lint and type-check` alone would leave a red documentation build outside
the required checks entirely. It moved from `lint.yml` to `docs.yml`
without the rule changing, which is worth knowing before renaming
anything — a context is matched by name, not by the workflow that reported
it, so moving a job is free and renaming one is not.

Neither `macos.yml`, `latest.yml`, `links.yml`, `mutation.yml`,
`published.yml` nor `vendored-vectors.yml` appears in the rule, and none of
them must: each is expected to go red for a reason no pull request
introduced. `macos.yml` is the one worth naming twice, because it does run
the suite: what a merge no longer waits for is the platform whose runners
queue for tens of minutes, measured in `test.yml`'s header, and
`release.yml` calls it so that a publication still does.

Each check is bound to the app that produces it — `checks` with an `app_id`
rather than the bare `contexts` list — so nothing else can satisfy one.
15368 is Actions and 57789 is `github-advanced-security`, which is the app
that reports `CodeQL`: the two Actions jobs of code scanning's default setup
are called `Analyze (actions)` and `Analyze (python)`, and the `CodeQL`
context is a separate check run that appears seconds after both finish.
Reading it too early is how one concludes that the rule names a context
nothing produces:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/commits/<sha>/check-runs \
  --jq '.check_runs[] | {name, app: .app.slug, app_id: .app.id}'
```

```shell
gh api repos/btclib-org/btclib-libsecp256k1/commits/<sha>/check-runs \
  --jq '[.check_runs[] | {name, app: .app.slug}] | unique_by(.app)'
```

**CodeQL is code scanning's default setup, not a workflow of this
repository** — `state: configured`, python and actions, the default query
suite, weekly — so there is no file here to read its triggers off:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/code-scanning/default-setup
```

That absence of a file is also why the check was first left out of the
rule, on a measurement that was the wrong one: it was taken on a pull
request against the branch that used to sit between a contributor and the
trunk, and default setup analyzes push events on the default branch and
pull requests *against* it, nothing else — so a pull request like #43
produced no CodeQL check run at all, measured, zero analyses. With `main`
the only long-lived branch every pull request is the kind default setup
analyzes, which is the kind #21, the 0.7.1 release merge, already was:
its analyses are under `refs/pull/21/head`.

```shell
gh api repos/btclib-org/btclib-libsecp256k1/code-scanning/analyses \
  --jq '.[] | {ref, category, created_at}'
```

`Dependency Graph` is not a candidate either: its runs are `dynamic`,
GitHub submitting the graph after a push rather than checking a pull
request.

**PATCH the sub-endpoint, never PUT the whole protection object**: a
partial PUT drops the reviews, the signatures and the rest. And `-F`,
not `-f`, for `strict` — `gh api`'s `-f` sends every value as a string,
and GitHub refuses `"true"` where a boolean is declared:

```shell
sub=branches/main/protection/required_status_checks
gh api "repos/{owner}/{repo}/$sub" -X PATCH -F strict=true \
  -F 'checks[][context]=test: every job passed' -F 'checks[][app_id]=15368' \
  -F 'checks[][context]=Lint and type-check' -F 'checks[][app_id]=15368' \
  -F 'checks[][context]=Build the documentation' -F 'checks[][app_id]=15368' \
  -F 'checks[][context]=CodeQL' -F 'checks[][app_id]=57789'
```

Renaming a required check is the one change that cannot be made in a pull
request. The rule names a context by the job's display name, so the pull
request that renames the job stops producing the old name and never
produces the one the rule is still waiting for. The rule moves first,
against the branch, and then the pull request that renames the job reports
the name the rule now wants; `enforce_admins` being off is what makes the
window survivable rather than a lock. Every open pull request that predates
the rename is blocked until it is rebased, which is the reason to do it
with none open but the one doing the renaming.

## Branch protection

`main`, all of it read from the endpoint above: `strict` with the four
checks already described, one approving review with
`dismiss_stale_reviews`, **required signatures**, linear history, no force
pushes, no deletions, `required_conversation_resolution`, and
`enforce_admins` **off** — an administrator can bypass all of it, matching
btclib now and for the same reason: a solo-maintainer repository cannot
satisfy "one approving review" from the author, GitHub refusing
self-approval, so the review is a stop rather than a speed bump, and the
admin bypass is the only way past it without a second maintainer to add.

```shell
gh api -X DELETE \
  repos/btclib-org/btclib-libsecp256k1/branches/main/protection/enforce_admins
```

Turned off after being on through the 0.7.1 release, whose squash merge
(see RELEASING.md) is what the previous setting actually cost: with
`enforce_admins` on, neither the force push nor the six unsigned commits
among the ninety-two the development branch carried could have gone back
onto the trunk, admin included. Off would not undo that squash today
either — that commit is what PyPI's PEP 740 attestations for 0.7.1 are
bound to, and moving it now would desynchronize a published release from
what it attests to rather than restore anything. What changed is only
whether the next incident has the same escape hatch btclib already keeps.

One protected branch is the whole of it, which is a consequence of there
being one long-lived branch:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/branches \
  --jq '.[] | "\(.name) protected=\(.protected)"'
```

The minimal rule that used to sit on the development branch — no force
pushes, no deletions, linear history, and nothing else — went with the
branch it protected. Nothing was weakened by that: what it guarded was a
trunk a pull request did not have to pass through, and every change now
reaches `main` through the rules above.

## Head branches after a merge

`delete_branch_on_merge` is on, since 7 August 2026:

```shell
gh api repos/btclib-org/btclib-libsecp256k1 --jq '.delete_branch_on_merge'
```

GitHub deletes the head branch of a pull request when it is merged, which
is what keeps the branch list a list of live work rather than a history of
every change ever made. It was turned on after a sweep that removed five
merged head branches from here, none of which anybody could tell from live
work without comparing each against the trunk commit by commit.

The case it does not cover is deliberate: a pull request **closed without
merging** keeps its head branch, GitHub having no way to know whether that
work was abandoned or is waiting, so those are the ones still worth
looking at now and then. The setting has a second exception — a protected
branch is never deleted, protection winning over it — which used to reach
the release pull request, whose head branch was protected. No head branch
is protected now.

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more declares it:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/actions/permissions/workflow \
  --jq '.default_workflow_permissions'   # "read"
```

Only `release.yml` asks for more: `contents: write` on `github-release`,
`id-token: write` on the two publish jobs, which is what Trusted
Publishing exchanges, and `id-token: write` with `attestations: write` on
`attest`. One elevation per job is the shape to keep — the job that writes
releases holds no OIDC token, and the job that signs writes no release.
The workflow-level `permissions: contents: read` in every file is belt and
braces; keep it, it is what makes the intent readable where the job is.

## Publishing

Both environments require a review, so an upload waits for a person:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/environments \
  --jq '.environments[] | {name, protection_rules}'
```

`pypi` and `testpypi` each have `fametrano` as the required reviewer.
`pypi` carries a deployment branch policy besides — one custom rule
admitting the tag pattern `v*`, that environment being reachable only from
a tag — while `testpypi` has none, being reached from a branch by
dispatch:

```shell
gh api repos/{owner}/{repo}/environments/pypi/deployment-branch-policies
# {"name": "v*", "type": "tag"}
```

The asymmetry is worth reading rather than assuming: a policy admitting
branches alone would refuse the deployment *after* the whole matrix had
been built, and no rehearsal would reveal it, reaching the other
environment.

What that rule constrains is the *name* of the ref and nothing else. A
`v*` tag pushed on a branch head, on a stale state or on a fork-synced
commit satisfies it exactly as the release tag does, so it is not the
check that a release is a release: the `version-check` job of
`release.yml` fails a tag that is not an ancestor of `main`, before the
matrix builds anything. [RELEASING.md](RELEASING.md) has the rest,
including what a mismatched trusted publisher looks like and why
self-review stays allowed.

**On TestPyPI the project is not ours.** The name carries an unrelated
`0.0.1` from 2021, and a trusted publisher can only be registered by an
owner: what unblocked the rehearsal of 0.7.1 was being made one, which is
a permission granted rather than a project owned. If a rehearsal ever
fails again with `invalid-publisher`, that is the first thing to check.

## Dependabot

Three ecosystems, and none of them names a target: with no
`target-branch` Dependabot opens against the default branch, which is the
only branch a change lands on. A setting that names nothing cannot name
something that is gone, which is what the `dev` it used to name became.

```shell
gh api repos/{owner}/{repo}/contents/.github/dependabot.yml \
  --jq '.content' | base64 -d | grep -E 'package-ecosystem|target-branch'
```

`github-actions` moves the SHA pins, `uv` the locked dependencies, and
`gitsubmodule` signals that the vendored secp256k1 has moved upstream —
which tracks the upstream *default branch*, so a release still needs a
manual bump to the tagged commit. `.github/dependabot.yml` is validated by
the `check-dependabot` hook, a typo there otherwise updating nothing and
saying nothing. Dependabot security updates are on.

## Plan-gated settings

Some settings cannot be enabled and fail silently:

```shell
gh api repos/btclib-org/btclib-libsecp256k1 --jq '.security_and_analysis'
```

Secret scanning and push protection are enabled;
`secret_scanning_non_provider_patterns` and
`secret_scanning_validity_checks` are `disabled` and cannot be turned on,
those needing paid Secret Protection. The API answers a PATCH with 200 and
leaves them off — **do not read that 200 as success.** The
`detect-secrets` hook is the compensating control, and CONTRIBUTING.md
carries what maintaining its baseline costs.

## Topics

The topics are `pyproject.toml`'s `keywords`, entry for entry: one list
spelled in two places, and the same spelling in both is what lets a drift
between them be seen at all. Lowercase throughout, a GitHub topic being
lowercase or not a topic. They were set on 7 August 2026, from the list #81
wrote: that pull request could change the packaging metadata and not the
repository, these settings living outside the tree, which is why it landed
with the topics still empty.

Nothing in the tree holds the two lists together, so this is the command
that does: it prints the difference and exits nonzero on one.

```shell
diff <(gh api repos/{owner}/{repo} --jq '.topics[]' | sort) \
     <(sed -n '/^keywords=\[/,/^]/s/^ *"\(.*\)",$/\1/p' pyproject.toml \
       | sort)
```

Both sides are sorted because GitHub returns the topics in an order of
its own rather than the one it was given: a reordering there is not
drift, and only `pyproject.toml`'s order is the deliberate one. The
comment above the `keywords` list says what decided it, and why `musig2`
and `bip324` are in a list of what this package wraps.

## No website

Unlike btclib, this repository serves no GitHub Pages site, so no file in
its root is a URL anywhere:

```shell
gh api repos/btclib-org/btclib-libsecp256k1/pages   # 404
```

btclib.org is built from the btclib repository's `main` root, which is
why that project's README is also a web page and this one's is not.
