<!-- a pull request body is a fragment of a page, not a document of its
     own: a top-level heading here would be a heading inside the issue
     view. Suppressed for the one line below rather than for the file, and
     by the rule's name rather than its number, so a heading added later is
     still checked. The suppression has to sit immediately above the
     heading, `disable-next-line` reaching exactly one line -- with this
     comment between the two it silenced the comment and MD041 still
     fired. Targets main, the only branch a change lands on. -->

<!-- markdownlint-disable-next-line first-line-heading -->
## What this changes, and why

<!--
The why is the part a reader cannot recover from the diff. Link the issue
this closes, if there is one: "Closes #123".
-->

## How it was verified

<!--
The command you ran and what it answered, the test that covers the change,
the vector it reproduces. This repository asks for a measurement rather than
a claim -- see the "Verifying, rather than reasoning about, a change"
section of CLAUDE.md -- and for a wrapper the vector has to come from
somewhere other than these bindings: their own output agreeing with itself
proves nothing.

A claim about the build matrix is measurable too: `gh run view <id>
--log-failed` reads better than a prediction of what CI will say.
-->

## Checklist

<!-- Delete what does not apply; an unchecked box is a fine thing to
     explain rather than hide. See CONTRIBUTING.md. -->

- [ ] `uv run pre-commit run --all-files` passes
- [ ] `uv run pytest --cov` passes, the coverage ratchet included
- [ ] new wrapped functionality is validated against vectors published
      elsewhere, not against these bindings' own output
- [ ] comments that this change makes untrue have been updated, in the
      workflows and build scripts too
- [ ] `CHANGELOG.md` has an entry for it, under the open version, and
      `RELEASE_NOTES.md` mentions it if a user of the package would
      notice. Both are written as the change lands, not at release
      time: the reasoning is here now and nowhere in three months
- [ ] the `secp256k1` submodule is untouched, or moving it is what this
      pull request is about and the version named in `README.md` moved
      with it

## Anything the reviewer should know

<!--
A decision you are unsure of, an alternative you rejected and why, a
specification that is ambiguous, a follow-up left out on purpose. This is
the same thing the comments in this repository are asked for -- the
reasoning including the negative result -- and it is what stops a reviewer
from proposing the thing you already tried.

Delete the section if there is none.
-->
