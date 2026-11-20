# AWS setup for auto-rca (OIDC, no stored keys)

`auto-rca.yml` no longer uses `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.
Instead, each run gets **short-lived credentials** from AWS by proving it is
*this repo's workflow on `main`* via GitHub's OIDC token
([THREAT_MODEL](../THREAT_MODEL.md) T8, T9).

Why this matters: a static key that leaks stays valid until someone notices
and revokes it. An OIDC session expires on its own (default 1 hour) and can
only be requested by the exact repo + branch named in the trust policy.

## One-time setup (≈10 minutes)

Replace `<ACCOUNT_ID>`, `<REGION>`, `<OWNER>/<REPO>`, `<LOG_GROUP_NAME>`
in the two JSON files in [`docs/iam/`](iam/) first.

**1. Add GitHub as an identity provider** (skip if your account already has it):

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

**2. Create the role** that only this repo's `main` branch can assume:

```bash
aws iam create-role \
  --role-name logmortem-auto-rca \
  --assume-role-policy-document file://docs/iam/trust-policy.json
```

**3. Attach least-privilege permissions.** Logmortem makes exactly one AWS
call (`logs:FilterLogEvents` in `src/collector.py`), so the role can read one
log group and nothing else:

```bash
aws iam put-role-policy \
  --role-name logmortem-auto-rca \
  --policy-name read-incident-log-group \
  --policy-document file://docs/iam/permissions-policy.json
```

**4. Repo secrets** (Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `AWS_ROLE_ARN` | `arn:aws:iam::<ACCOUNT_ID>:role/logmortem-auto-rca` |
| `AWS_DEFAULT_REGION` | optional, defaults to `us-east-1` |

**5. Delete the old secrets** `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
from the repo, then **deactivate and delete that access key in IAM**.
Removing it from GitHub isn't enough; the key itself is still valid until
it's revoked in AWS.

## Troubleshooting

`Not authorized to perform sts:AssumeRoleWithWebIdentity` almost always
means the `sub` condition doesn't match. `workflow_run` jobs run on the
default branch, so `sub` should be `repo:<OWNER>/<REPO>:ref:refs/heads/main`.
If your default branch isn't `main`, change it in `trust-policy.json`.
