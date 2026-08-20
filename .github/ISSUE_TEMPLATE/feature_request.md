---
name: Feature request
about: Suggest a new feature or behavior change
title: "[feature] "
labels: ["enhancement", "needs-triage"]
assignees: []
---

## Problem

What problem does this solve? "I want to …" or "It would be nice if …".

## Proposed solution

Describe the desired behavior in enough detail that someone could
implement it.

## Alternatives considered

What other approaches did you think about, and why is this one better?

## Wire / API impact

Will this change:

- the signed-UUID format?
- the VLESS Encryption profile (handshake, key schedule, AEAD)?
- the public Worker URL shape (`/sub?token=…`)?
- the `wrangler.toml` schema?
- a client-side configuration?

If yes to any, please detail.

## Backward compatibility

How do existing deployments keep working after this lands?

## Checklist

- [ ] I have searched existing issues / discussions
- [ ] I am willing to submit a PR (or would welcome someone else to)
