# Contributing to lib-conclave-sdk

This repository adopts Conxian Labs' parent governance defaults from `Conxian/.github` for policy, templates, and control workflows.

## Protocol for Contributions

We use [GitHub Flow](https://guides.github.com/introduction/flow/index.html). All changes must occur through Pull Requests (PRs).

### 1. Preparation
- Create your branch from the repository default branch.
- Ensure your proposed change is aligned with repository architecture and security posture.

### 2. Implementation
- Keep diffs precise and scoped.
- Update relevant docs/policies when controls or behavior change.
- Run the repo's relevant local checks before requesting review.

### 3. Submission
- Link a tracking issue (for example, `CON-727`) in your PR.
- Complete the PR security/governance checklist in `.github/PULL_REQUEST_TEMPLATE.md`.
- If sensitive files changed, obtain required CODEOWNERS review before merge.
- By contributing, you agree your work is licensed under this repository's [MIT License](LICENSE).

## Sensitive File Changes

Changes to the following files require CODEOWNERS review and adherence to the PR security checklist:

- `CODEOWNERS`
- `SECURITY.md`
- `SUPPORT.md`
- `.github/ISSUE_TEMPLATE/**`
- `.github/PULL_REQUEST_TEMPLATE*`
- `.github/workflows/**`
- `.github/release.yml`

## Support and Security Routing

Use the GitHub issue tracker in this repository for public discussions.

For support routing, refer to [SUPPORT.md](SUPPORT.md).

For security vulnerabilities, refer to [SECURITY.md](SECURITY.md).
