# OIDC Federation Runbook — GitHub Actions → AWS

Replaces long-lived AWS access keys with short-lived, repo-scoped OIDC role
credentials for the `provision-nitro` workflow. This removes the
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` repository secrets (a
single-signer / credential-exfiltration risk) and the `conxian-sdk-signer` /
`conxian-agent` long-lived keys.

## Prerequisites

An IAM principal with `iam:CreateOpenIDConnectProvider`, `iam:CreateRole`,
`iam:AttachRolePolicy`, `iam:DeleteAccessKey`, and `iam:DeleteRole` (an IAM
admin such as `botshelo`, or the AWS account root via the console). The
`conxian-agent` principal does **not** have these permissions.

## Step 1 — Apply the CloudFormation stack

```bash
aws cloudformation create-stack \
  --stack-name conxian-oidc-federation \
  --template-body file://scripts/nitro/iam/oidc-federation.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region eu-central-1
```

Console alternative: CloudFormation → Create stack → upload
`scripts/nitro/iam/oidc-federation.yaml`.

This creates:

- The GitHub OIDC provider (`token.actions.githubusercontent.com`).
- The `github-actions-provision-nitro` role — trust-anchored to
  `repo:Conxian/conxius-enclave-sdk:*` via OIDC, with least-privilege EC2
  (Nitro) + IAM (Nitro role wiring) + `sts:GetCallerIdentity`. No KMS, no
  long-lived keys.

## Step 2 — Verify the role is assumable from GitHub

Run the `provision-nitro` workflow once (Actions → provision-nitro → Run
workflow). The `Configure AWS credentials` step must succeed without any repo
secret. If it fails with `AccessDenied` on `AssumeRoleWithWebIdentity`, confirm
the stack applied and the workflow's `id-token: write` permission is present.

## Step 3 — Delete the long-lived credentials

1. Remove the repo secrets `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
   (Settings → Secrets and variables → Actions). `provision-nitro.yml` no
   longer references them.
2. Delete the `conxian-sdk-signer` access keys (both), after confirming the CI
   runs on OIDC. The stale `us-east-1` key can go first.
3. Delete `conxian-agent`'s access key once the agent authenticates via
   `sts:AssumeRole` into an assumable admin role instead of a static key.

## Step 4 — Refresh the thumbprint (when GitHub rotates the cert)

GitHub rotates the `*.actions.githubusercontent.com` certificate periodically;
the OIDC provider thumbprint must stay current:

```bash
echo | openssl s_client -servername token.actions.githubusercontent.com \
  -connect token.actions.githubusercontent.com:443 2>/dev/null \
  | openssl x509 -fingerprint -sha1 -noout
```

Update the `ThumbprintList` in `scripts/nitro/iam/oidc-federation.yaml` (or the
live OIDC provider) with the new value (AWS allows up to 5 thumbprints so you
can stage the next value before rotation completes).

## Rollback

Re-add the two repo secrets and revert the `Configure AWS credentials` step to
`aws-access-key-id` / `aws-secret-access-key`. Re-enable any deleted access
key, or create a new one under the relevant IAM user.
