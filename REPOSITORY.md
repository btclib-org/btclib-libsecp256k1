# Repository configuration

Read this before changing a workflow, a branch rule or a repository
setting; writing code does not need it. [CLAUDE.md](CLAUDE.md) points here
rather than carrying it, so that a session fixing a wrapper does not hold
it in context.

The branch rules and the repository settings live *outside* the
repository, so this file is the whole of them: nothing here can be
recovered by reading the tree. Every value below was read from the API,
and the command that reads it is beside it.

## Required checks on master

**Never name matrix contexts in a branch rule.** The rule lives outside
the repository, so a context that stops being produced blocks every merge
with nothing in the tree to explain why — and the matrix here is
`Test ${{ matrix.python-version }} on ${{ matrix.os }}`, whose contexts
change with every interpreter added or dropped. `tests-passed` is the
aggregate job at the end of `test.yml` that `needs` every other job in
it; a job added to that workflow belongs in its `needs` list, or it gates
nothing.

**As of this writing no check is required at all**, which is worth knowing
before reading anything else here:

    gh api repos/btclib-org/btclib_libsecp256k1/branches/master/protection \
      --jq '.required_status_checks'
    # {"strict": true, "checks": [], "contexts": [], ...}

`strict: true` requires a branch to be up to date with `master`; the empty
list is what says that no *particular* check has to pass. So a pull
request whose matrix is red can be merged once it carries a review.

Two checks are candidates for a rule, and they are the two a pull request
actually produces — measured, rather than read off the workflow files:

| Check | Produced by |
| --- | --- |
| `tests-passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, its only job |

    gh api repos/btclib-org/btclib_libsecp256k1/commits/<sha>/check-runs \
      --jq '[.check_runs[] | {name, app: .app.slug}] | unique_by(.app)'

**CodeQL is not among them, and that is a fact to check before naming
it.** It is code scanning's default setup rather than a workflow of this
repository — `state: configured`, python and actions, the default query
suite, weekly — so there is no file here to read its triggers off, and on
the pull requests measured it produced no check run at all. Naming a
check that a pull request does not produce is what blocks every merge
with nothing in the tree to explain why.

    gh api repos/btclib-org/btclib_libsecp256k1/code-scanning/default-setup

`Dependency Graph` is not a candidate either: its runs are `dynamic`,
GitHub submitting the graph after a push rather than checking a pull
request.

Binding each named check to the app that produces it — `checks` with an
`app_id` rather than the bare `contexts` list, 15368 for Actions — is what
keeps anything else from satisfying one.

**PATCH the sub-endpoint, never PUT the whole protection object**: a
partial PUT drops the reviews, the signatures and the rest.

    sub=branches/master/protection/required_status_checks
    gh api "repos/{owner}/{repo}/$sub"

## Branch protection

`master`, all of it read from the endpoint above: `strict` with the empty
check list already described, one approving review with
`dismiss_stale_reviews`, **required signatures**, linear history, no force
pushes, no deletions, `required_conversation_resolution`, and
`enforce_admins` **on** — which is the one place this repository is
*stricter* than btclib, where an administrator can bypass.

`dev` is **not protected**:

    gh api repos/btclib-org/btclib_libsecp256k1/branches/dev/protection
    # {"message": "Branch not protected", "status": "404"}

That is where Dependabot and pre-commit.ci push, and where every branch
is cut from, so it can be force-pushed or deleted under an open pull
request. btclib protects its own `dev` with no force pushes, no
deletions and linear history, and nothing else — no required check, no
review, no signature, so a direct push still works, which is what both
bots rely on. Requiring signatures there would reject every bot commit,
and one approving review cannot be satisfied by the author.

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more declares it:

    gh api repos/btclib-org/btclib_libsecp256k1/actions/permissions/workflow \
      --jq '.default_workflow_permissions'   # "read"

Only `release.yml` asks for more: `contents: write` on `github-release`,
and `id-token: write` on the two publish jobs, which is what Trusted
Publishing exchanges. The workflow-level `permissions: contents: read` in
every file is belt and braces; keep it, it is what makes the intent
readable where the job is.

## Publishing

Both environments require a review, so an upload waits for a person:

    gh api repos/btclib-org/btclib_libsecp256k1/environments \
      --jq '.environments[] | {name, protection_rules}'

`pypi` and `testpypi` each have `fametrano` as the required reviewer.
`pypi` carries a deployment branch policy besides — one custom rule
admitting the tag pattern `v*`, that environment being reachable only from
a tag — while `testpypi` has none, being reached from a branch by
dispatch:

    gh api repos/{owner}/{repo}/environments/pypi/deployment-branch-policies
    # {"name": "v*", "type": "tag"}

The asymmetry is worth reading rather than assuming: a policy admitting
branches alone would refuse the deployment *after* the whole matrix had
been built, and no rehearsal would reveal it, reaching the other
environment. [RELEASING.md](RELEASING.md) has the rest, including what a
mismatched trusted publisher looks like and why self-review stays
allowed.

**On TestPyPI the project is not ours.** The name carries an unrelated
`0.0.1` from 2021, and a trusted publisher can only be registered by an
owner: what unblocked the rehearsal of 0.7.1 was being made one, which is
a permission granted rather than a project owned. If a rehearsal ever
fails again with `invalid-publisher`, that is the first thing to check.

## Dependabot

Three ecosystems, and all three target `dev`, `master` only receiving
merges from it:

    gh api repos/{owner}/{repo}/contents/.github/dependabot.yml \
      --jq '.content' | base64 -d | grep -E 'package-ecosystem|target'

`github-actions` moves the SHA pins, `uv` the locked dependencies, and
`gitsubmodule` signals that the vendored secp256k1 has moved upstream —
which tracks the upstream *default branch*, so a release still needs a
manual bump to the tagged commit. `.github/dependabot.yml` is validated by
the `check-dependabot` hook, a typo there otherwise updating nothing and
saying nothing. Dependabot security updates are on.

## Plan-gated settings

Some settings cannot be enabled and fail silently:

    gh api repos/btclib-org/btclib_libsecp256k1 --jq '.security_and_analysis'

Secret scanning and push protection are enabled;
`secret_scanning_non_provider_patterns` and
`secret_scanning_validity_checks` are `disabled` and cannot be turned on,
those needing paid Secret Protection. The API answers a PATCH with 200 and
leaves them off — **do not read that 200 as success.** The
`detect-secrets` hook is the compensating control, and CONTRIBUTING.md
carries what maintaining its baseline costs.

## No website

Unlike btclib, this repository serves no GitHub Pages site, so no file in
its root is a URL anywhere:

    gh api repos/btclib-org/btclib_libsecp256k1/pages   # 404

btclib.org is built from the btclib repository's `master` root, which is
why that project's README is also a web page and this one's is not.
