<!-- markdownlint-disable-file MD041 -->
<!-- a pull request body is a fragment of a page, not a document of its
     own: a top-level heading here would be a heading inside the issue
     view. Targets dev; master only ever receives merges from it. -->

## What this changes, and why

<!--
The why is the part a reader cannot recover from the diff. Link the issue
this closes, if there is one.
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
- [ ] `HISTORY.md` mentions it, if a user of the package would notice
- [ ] the `secp256k1` submodule is untouched, or moving it is what this
      pull request is about and the version named in `README.md` moved
      with it
