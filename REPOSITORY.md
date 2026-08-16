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
gh api repos/btclib-org/btclib-secp256k1/branches/main/protection \
  --jq '.required_status_checks'
```

| Check | Produced by |
| --- | --- |
| `test: every job passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, its only job |
| `Build the documentation` | `docs.yml`, its only job |

`codeql: every job passed` is not among them, and that is the one place a
check was traded for the slots it held. GitHub Free gives an organization
twenty concurrent jobs, shared across every repository in it: this one asked
for seventy-three on every commit, btclib for thirty-nine and
bitcoin-core-rpc for forty-four, so a pull request in any of the three
waited for a slot rather than for the work. `codeql.yml` now runs on `main`
and on its Tuesday schedule, the analysis landing on the merge commit rather
than ahead of it, and it still produces that aggregate — the name is
available, so requiring it again is a patch to the rule and nothing in the
tree.

What still reads a branch before it merges is the workflow half of the same
question: `zizmor` is a `pre-commit` hook, so `lint.yml` audits these very
files for an injected expression on every pull request, and that check is
required. What a merge defers is the rest of the analysis, for the time
between that merge and the next run — which for `main` is the merge itself.

`Build the documentation` is named on its own on purpose: a rule naming
`Lint and type-check` alone would leave a red documentation build outside
the required checks entirely. It moved from `lint.yml` to `docs.yml`
without the rule changing, which is worth knowing before renaming
anything — a context is matched by name, not by the workflow that reported
it, so moving a job is free and renaming one is not.

`pre-commit.ci` is not in the rule either, and it is the one check here
this repository cannot make agree with `lint.yml`. It runs the hooks of
`.pre-commit-config.yaml` from a checkout of its own, and one hook needs
more than that checkout gives: `submodule-pin` resolves the release
`README.md` names in the vendored clone's refs. `submodules: true` under
`ci:` is the documented key for the clone, and it was tried on #132 rather
than reasoned about — with it the submodule arrives and the hook still
fails, `the vendored clone is shallow and carries no v0.8.0 tag`. There is
no `fetch-depth` key to ask that service for, so the hook is in the `ci:`
`skip` list beside `pyroma`, which needs a network that service also does
not give. What that costs is one of the hook's two runners: the one the
rule names, `Lint and type-check`, checks the submodule out with
`fetch-depth: 0` precisely so it has what the hook needs, and so does a
developer's own commit. Re-read that skip list before adding to it: an
entry may join for a reason of that kind and no other.

Neither `macos.yml`, `windows.yml`, `latest.yml`, `links.yml`,
`mutation.yml`, `published.yml` nor `vendored-vectors.yml` appears in the
rule, and none of them must: each is expected to go red for a reason no pull
request introduced. `macos.yml` and `windows.yml` are the two worth naming
twice, because they do run the suite: what a merge no longer waits for is
the platform whose runners queue for tens of minutes and the one whose cells
were the largest family of jobs in a run, both measured in `test.yml`'s
header and theirs, and `release.yml` calls both so that a publication still
does.

A check can be bound to the app that produces it — `checks` with an
`app_id` rather than the bare `contexts` list — so that nothing else can
satisfy it, and 15368 is Actions, which produces them all. All three carry
that binding, and the two that did not are why it is worth stating: an
unbound context reads `app_id: null` and is satisfied by *any* app
reporting a check run of that name, so anything installed on the
organization with `checks: write` could turn one green with no workflow
having run. A `PATCH` dates that sentence, so read it back rather than
trust it:

```shell
gh api repos/btclib-org/btclib-secp256k1/branches/main/protection \
  --jq '[.required_status_checks.checks[] | {context, app_id}]'
```

Which app reported what is read from the commit rather than assumed:

```shell
gh api repos/btclib-org/btclib-secp256k1/commits/<sha>/check-runs \
  --jq '.check_runs[] | {name, app: .app.slug, app_id: .app.id}'
```

```shell
gh api repos/btclib-org/btclib-secp256k1/commits/<sha>/check-runs \
  --jq '[.check_runs[] | {name, app: .app.slug}] | unique_by(.app)'
```

**CodeQL is `.github/workflows/codeql.yml`, and code scanning's default
setup is off** — the two are mutually exclusive, and what that costs is not
a workflow GitHub declines to start. The workflow runs, the analysis
completes, the SARIF uploads, and processing answers:

```text
Code Scanning could not process the submitted SARIF file:
CodeQL analyses from advanced configurations cannot be processed when
the default setup is enabled
```

So while the setting is on the analysing jobs and the aggregate are red
rather than absent, and the file is still the one that can be reviewed in a
diff. What the setting holds is read from the endpoint, `state` being the
field that says whether it holds anything:

```shell
gh api repos/btclib-org/btclib-secp256k1/code-scanning/default-setup
```

Turning the setting off takes `state` and nothing else — the languages, the
query suite and the runner it also accepts describe an analysis that is not
going to run:

```shell
gh api -X PATCH \
  repos/btclib-org/btclib-secp256k1/code-scanning/default-setup \
  -F state=not-configured
```

The order matters in both directions, and it is the branch rule that
decides it: while the setting is on, `codeql.yml` produces a red
`codeql: every job passed` rather than none at all, and while it is off,
nothing produces that context until the workflow has run. So the rule drops
the `CodeQL` context first, the setting moves second, the checks are
re-run, and the rule names the new context last — each step leaving the
merge path open, where any other order closes it on a context nothing
reports. `enforce_admins` being off is what makes that window survivable
rather than a lock.

That exchange has been made: the endpoint above answers `not-configured`.
What the rule does *not* name any more is `codeql: every job passed`, for
the reason the section above gives — so the last step of that order was
undone afterwards, deliberately, and the order is kept here because the
setting can be configured again and because requiring the context again is
the same `PATCH` with one entry more.

A `CodeQL` check and an `Analyze (python)` job outlive it, and neither
comes from this tree: GitHub keeps a generated
`dynamic/github-code-scanning/codeql` workflow, which uploads *code
quality* results rather than security ones — `python.quality.sarif` in its
log, where the security analysis produced `python.sarif`. That is a
separate setting with an endpoint of its own, the "Code quality" section
below, and the endpoint above reports nothing about it:

```shell
gh api repos/btclib-org/btclib-secp256k1/actions/workflows \
  --jq '.workflows[] | select(.path | startswith("dynamic/"))
        | {name, path, state}'
```

What the file asks for is read off its own triggers; what was actually
analyzed, and under which ref and category, is the API's answer:

```shell
gh api repos/btclib-org/btclib-secp256k1/code-scanning/analyses \
  --jq '.[] | {ref, category, analysis_key, created_at}'
```

The category is what ties an upload to the ones before it, so
`codeql.yml` spells it exactly as the setting did, `/language:python` and
`/language:actions`: an upload under a new category closes every open alert
as fixed and opens a copy of it. The `analysis_key` is the one thing that
does change, from `dynamic/github-code-scanning/codeql:analyze` to this
workflow's path, and no alert is keyed on it.

`Dependency Graph` is not a candidate for the rule either: its runs are
`dynamic`, GitHub submitting the graph after a push rather than checking a
pull request.

**PATCH the sub-endpoint, never PUT the whole protection object**: a
partial PUT drops the reviews, the signatures and the rest. And `-F`,
not `-f`, for `strict` — `gh api`'s `-f` sends every value as a string,
and GitHub refuses `"true"` where a boolean is declared:

```shell
sub=branches/main/protection/required_status_checks
gh api "repos/{owner}/{repo}/$sub" -X PATCH -F strict=true \
  -F 'checks[][context]=test: every job passed' -F 'checks[][app_id]=15368' \
  -F 'checks[][context]=Lint and type-check' -F 'checks[][app_id]=15368' \
  -F 'checks[][context]=Build the documentation' -F 'checks[][app_id]=15368'
```

`checks[][…]` repeated is how one array of objects is written: `-F` pairs
each `context` with the `app_id` that follows it, and sends the number as a
number. Reading the body before sending it is a probe against a path that
does not exist, which reports a 404 and changes nothing:

```shell
gh api --verbose -X POST "repos/{owner}/{repo}/zzz-probe" \
  -F 'checks[][context]=A' -F 'checks[][app_id]=15368' \
  | sed -n '/^{/,/^}/p'
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

## Code quality

The analysis the generated workflow above was left running, and it is off.
Its setting is not `code-scanning/default-setup`, and the Actions API is
not the way in either: a generated workflow is not one this repository
owns, and `actions/workflows/<id>/disable` answers 422. The endpoint that
reports the setting is the one that sets it:

```shell
gh api repos/btclib-org/btclib-secp256k1/code-quality/setup
# {"state":"not-configured","languages":["python"], ...}

gh api -X PATCH repos/btclib-org/btclib-secp256k1/code-quality/setup \
  -F state=not-configured
```

What decided it is the ceiling the section above already trades against,
not the queries. `Analyze (python)` ran on every pull request and every
push to `main` — `Code Quality: PR #N` in the run list — for some 52
seconds of a slot each time, and the twenty concurrent jobs are shared
with every other repository in the organization, where the same setting
was on.

What it produced in exchange cannot be read from outside a browser. There
is no `code-quality/alerts` and no `code-quality/analyses`, both 404, and
a quality upload appears in neither endpoint that does answer: the alert
list is empty, and every analysis carries `codeql.yml`'s own category.

```shell
gh api "repos/btclib-org/btclib-secp256k1/code-scanning/alerts?per_page=100" \
  --jq length
gh api "repos/btclib-org/btclib-secp256k1/code-scanning/analyses?per_page=100" \
  --jq '[.[] | .category] | unique'
```

`state=configured` is the way back, and the argument for it is that these
queries are a class of finding nothing else here makes: ruff, mypy and the
spell checkers are the cover, and they are not the same questions. What
refuses them is the ceiling, so a fleet not waiting for slots is what
would change the answer.

## Branch protection

`main`, all of it read from the endpoint above: `strict` with the three
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
  repos/btclib-org/btclib-secp256k1/branches/main/protection/enforce_admins
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
gh api repos/btclib-org/btclib-secp256k1/branches \
  --jq '.[] | "\(.name) protected=\(.protected)"'
```

The minimal rule that used to sit on the development branch — no force
pushes, no deletions, linear history, and nothing else — went with the
branch it protected. Nothing was weakened by that: what it guarded was a
trunk a pull request did not have to pass through, and every change now
reaches `main` through the rules above.

## The rulesets, and the push their bypass is for

Two rulesets sit on `main` beside that protection, and what separates
them is who may bypass:

```shell
gh api repos/btclib-org/btclib-secp256k1/rulesets \
  --jq '.[] | "\(.name) \(.enforcement) bypass=\(.bypass_actors | length)"'
```

`main-integrity` is the four CONTRIBUTING.md names — a verified
signature, linear history, no force push, no branch deletion — with **no
bypass actor at all**, which is what makes "on every commit, not at
review time" true of an administrator too, `enforce_admins` above being
off. `main-self-merge` is the pull request rule, and names the maintainer
as one; the listing above answers each ruleset's id, and the rules and
the bypass of either are read from it:

```shell
gh api repos/btclib-org/btclib-secp256k1/rulesets/<id> \
  --jq '{rules: [.rules[].type], bypass: [.bypass_actors[].actor_type]}'
```

The split is the point of there being two. The review is the rule a solo
maintainer cannot satisfy, GitHub refusing a self-approval; the integrity
four are the rules nobody should be able to. One ruleset each is what
lets the first be bypassed without the second going with it.

**What the bypass is for is a push, not a button.** A reviewed branch
reaches `main` from the command line:

```shell
git fetch origin && git rebase origin/main   # replayed on the tip
git log --format='%h %G?' origin/main..      # every commit G, none N
git push origin HEAD:main                    # a fast-forward, nothing rewritten
```

Where the branch carries more than one commit it is squashed into a
single signed commit first — `git reset --soft origin/main && git
commit`, with `--author` where the branch is somebody else's, GitHub's
button being what would otherwise have kept their name on it — and that
commit is what the push fast-forwards.

**The bypass is not the whole of the permission.** The protection above
still carries `required_pull_request_reviews` and its `strict` required
checks, and what a push to `main` clears those with is `enforce_admins`
being `false` and the pusher holding `admin`; the ruleset bypass alone
would not be enough. So the path depends on two settings and not one,
and the fragile one is that: turning `enforce_admins` on closes the
fast-forward whatever the ruleset says, and moving the review
requirement onto a ruleset of its own is what would leave the bypass
answering for all of it.

What this buys is what no button can give. GitHub composes a squash
server-side and signs it with its own web-flow key, so the commit that
lands is `verified` with GitHub as the signer; a push signs nothing and
has nothing to sign, the commit arriving with the signature it already
carried. And where the branch was a single commit and the rebase moved
nothing, its sha does not change either, so `main` receives the very
commit the gates ran on and a branch stacked on that one keeps applying
instead of needing a rebase and a fresh run of the matrix per level.
Where the rebase did move it, re-running the gates after it is what buys
that back — and it is discipline on this path rather than a rule, the
`strict` above being one of the things the push clears. What `strict`
holds is the merge nobody performs here.

**Whether GitHub reconciles the push depends on one thing: whether what
lands is the sha the pull request names at that moment**, a pull request
being marked merged when its head becomes reachable from the base
branch.

- **it names what lands** — the branch's own head is fast-forwarded,
  whether it reached that shape as one commit or as a squash **pushed to
  the branch first**, and a rebase force-pushed to the branch is this
  case too. GitHub marks the pull request **Merged** on its own, and the
  `Closes #N` in its description closes the issue.
- **it names something else** — the squash or the rebase was made
  locally and pushed straight to `main`. What lands is an object no pull
  request names, so nothing is reconciled: close it by hand, and let the
  issue close from the `Closes #N` in the *commit message*, which is the
  reason for the keyword to be there and not only in the description.

Which is an argument for pushing the squash to the branch before landing
it, where the branch is one whose head may move: the matrix then runs on
the very object that will land rather than on a head that never will,
and the reconciliation does the closing. Measured in btclib the other
way, on the day this was written:
<https://github.com/btclib-org/btclib/pull/953> was squashed locally and
pushed straight to `main`, landing as `7f7a269b` — signed by the
maintainer, so both halves of the rule worked — and is **Closed** with
`mergedAt: null`, its issue having closed twenty-two seconds earlier
from the commit message. Which of the two happened is also what decides
when the head branch goes, and "Head branches after a merge" below is
where that is.

## Head branches after a merge

`delete_branch_on_merge` is on, since 7 August 2026:

```shell
gh api repos/btclib-org/btclib-secp256k1 --jq '.delete_branch_on_merge'
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

**It reaches one of the two landings above**, and which one is the
reconciliation again — the setting hangs on the merge GitHub records, so
it fires wherever GitHub records one:

- **the pull request named what landed**: nothing to do. Measured on
  <https://github.com/btclib-org/btclib-secp256k1/pull/185>, whose
  squash was pushed to the branch and then fast-forwarded: marked Merged
  at 12:39:19 and `head_ref_deleted` at 12:39:20, with nobody asking.
  What is left is not to get ahead of it — deleting the branch before
  the reconciliation is what leaves a pull request Closed with its
  commit on `main` all the same, as btclib's
  <https://github.com/btclib-org/btclib/pull/930> came out.
- **it named something else** — the squash or the rebase went straight
  to `main`: nothing is reconciled, so nothing is deleted either. Close
  the pull request by hand and delete the branch with it.

## Merge methods

**Squash is the only *button* enabled**, so it is a setting and not only
the convention CONTRIBUTING.md states:

```shell
gh api repos/btclib-org/btclib-secp256k1 \
  --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge}'
```

answers `true` for the first and `false` for the other two.

A button is not how a pull request lands here, and this section named one
as if it were: every merge is the fast-forward above, and the squash the
branch may need first is made locally. What that leaves the setting doing
is bounding the damage of a landing nobody drove from a shell — auto-merge
below is the one that reaches the button, and GitHub's key is what signs
what it presses.

The merge commit was refused by `main`'s required linear history already,
so turning it off takes away a button that could not have worked. The
rebase merge could have, and that is the one this removes: it replays a
branch's commits onto `main`, where one change is one commit and the steps
of a review belong to the pull request that carries them.

What a single method takes away is the dropdown. GitHub preselects
whichever method was used last, and the dialog below carries the same one,
so the answer could be given hours before anything merged and by whoever
switched auto-merge on. One method is one entry: there is no wrong one to
preselect, and nothing to read before pressing.

## Auto-merge

`allow_auto_merge` is on, since 11 August 2026:

```shell
gh api repos/btclib-org/btclib-secp256k1 --jq '.allow_auto_merge'
```

It bypasses nothing, and it is not the admin escape hatch above: GitHub
offers the button **only on a pull request that cannot be merged
immediately**, and then merges it when the last thing blocking it clears —
one of the three required checks, the approving review, an unresolved
conversation. Where nothing is pending there is nothing to wait for and the
button is not offered at all, so this setting does something here precisely
because the rule on `main` is what it is: the matrix is tens of jobs
compiling C, and `test.yml`'s header measures what waiting for it costs.

**Required signatures survive it**, measured rather than assumed, because
GitHub composes the squash commit server-side and signs it with its own key
exactly as the merge button does — its own key and not the author's, which
is the trade this setting makes and the fast-forward above is what does
not make it. Nor does every landing from a shell keep a signature:
`gh pr merge --rebase --admin` replays the author's commits as they were,
unsigned, where a fast-forward moves commits that were signed before it
was run. So the check is worth making on whatever landed, whichever way it
got there:

```shell
gh api repos/btclib-org/btclib-secp256k1/commits/<sha> \
  --jq '.commit.verification | {verified, reason}'
```

**What auto-merge will press was chosen when it was switched on, rather
than when the merge happened.** That dropdown carries one entry, squash
being the only button enabled — "Merge methods" above is the setting and
the reason — so switching auto-merge on answers nothing a reviewer has to
catch before it lands. The fast-forward is not in the dropdown at all,
being a push: a pull request left to merge itself is one that will not
land that way, and what it costs is the signature on the commit. Not
waiting for a matrix that compiles C on every platform is what is bought
with it. What a pull request is holding is still worth reading, the wait
itself being what this bypasses:

```shell
gh pr view <n> --json autoMergeRequest
```

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more declares it:

```shell
gh api repos/btclib-org/btclib-secp256k1/actions/permissions/workflow \
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
gh api repos/btclib-org/btclib-secp256k1/environments \
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
gh api repos/btclib-org/btclib-secp256k1 --jq '.security_and_analysis'
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
gh api repos/btclib-org/btclib-secp256k1/pages   # 404
```

btclib.org is built from the btclib repository's `main` root, which is
why that project's README is also a web page and this one's is not.
