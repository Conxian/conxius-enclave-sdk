PROMOTION:FEATURE->DEV

### Feature -> dev promotion checklist
- [x] I assessed whether this change affects security posture, threat model, or governance controls.
- [x] I verified no secrets, tokens, private keys, or sensitive internal data were introduced.
- [x] I updated documentation/policies where required.

## Summary

<!-- What changed and why? -->

## Security and Governance Checklist

- [x] I assessed whether this change affects security posture, threat model, or governance controls.
- [x] I verified no secrets, tokens, private keys, or sensitive internal data were introduced.
- [x] I updated documentation/policies (`SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, templates, workflows, `release.yml`) where required.
- [x] If sensitive files changed, I requested and obtained required CODEOWNERS review.
- [x] I linked the tracking issue (for example, `CON-176`).

## Sensitive Files (CODEOWNERS-enforced)

- `CODEOWNERS`
- `SECURITY.md`
- `SUPPORT.md`
- `.github/ISSUE_TEMPLATE/**`
- `.github/PULL_REQUEST_TEMPLATE*`
- `.github/workflows/**`
- `.github/release.yml`

## Linked issue

Closes #
