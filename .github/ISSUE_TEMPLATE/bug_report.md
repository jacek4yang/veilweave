---
name: Bug report
about: Something is broken or behaving incorrectly
title: "[bug] "
labels: ["bug", "needs-triage"]
assignees: []
---

## Summary

One-paragraph description of the bug.

## Steps to reproduce

```
1. …
2. …
3. …
```

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened. Paste the full `wrangler tail` excerpt (or
client-side log) here — please redact any UUID / proxyip.

## Environment

- Cloudflare account plan: free / paid
- Worker deployed: `relay` / `sub` / both
- Worker URL: `https://…` (redact if not your own)
- `wrangler --version`:
- `rustc --version`:
- Client + version: xray-core / sing-box / v2rayN / … + version
- Commit / tag: (e.g. `main` @ `abc1234`, or `v0.1.0`)

## Screenshots / logs

If applicable, attach a screenshot or paste logs.

## Possible cause

If you have an idea, share it — but no pressure to know the answer.

## Checklist

- [ ] I have searched existing issues and there is no duplicate
- [ ] I have not posted secrets (UUIDs, proxyip IPs, tokens)
- [ ] I have redacted any real `SECRET_KEY` from logs
