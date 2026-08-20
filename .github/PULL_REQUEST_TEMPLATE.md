## Summary

<!-- One or two sentences. -->

## What changed

<!-- Bullet list of the changes. -->

## Why

<!-- Motivation. Link the issue, if any. -->

## How I tested

<!-- Build, test commands, manual smoke test. -->

## Checklist

- [ ] I have read [`CONTRIBUTING.md`](../blob/main/CONTRIBUTING.md)
- [ ] I followed the code style of the surrounding code
- [ ] My change is on the hot path; I added a `vlog!` or perf comment if useful
- [ ] I have not committed any secret (`SECRET_KEY`, `VEILWEAVE_NODES`, `SUBSCRIPTION_TOKEN`)
- [ ] For wire-format changes: I have updated [`docs/protocol.md`](../blob/main/docs/protocol.md)
- [ ] For deployment-shape changes: I have updated [`docs/deployment.md`](../blob/main/docs/deployment.md)
- [ ] I have run `cargo fmt` and `cargo build` for the affected crate(s)
- [ ] I have added or updated tests where it makes sense

## Breaking change?

- [ ] Yes
- [ ] No

If yes, describe the migration path.

## Related

- Fixes / Closes / Refs: #issue-number
