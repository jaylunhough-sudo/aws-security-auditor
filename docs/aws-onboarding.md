# Connect your AWS account to Umber Cloud (15 minutes, read-only)

Umber Cloud never gets write access to your AWS account. You grant a read-only
view scoped to security metadata — the same access model used by every major
agentless scanner. Two options below; Option B is what the hosted product uses.

## Option A — quick start with an IAM user (solo founders, evaluating)

1. Sign in to the AWS console → **IAM** → **Users** → **Create user**
2. Name: `umber-cloud-auditor`. Do **not** enable console access. → Next
3. **Attach policies directly** → search `SecurityAudit` → check the
   AWS-managed **SecurityAudit** policy → Create user
4. Open the user → **Security credentials** → **Access keys** →
   **Create access key** → use case **CLI** → create and copy both values
5. On your machine:

```bash
aws configure --profile umber-cloud-auditor
# paste the two keys; region us-east-1; output json
```

6. Verify, then scan:

```bash
aws sts get-caller-identity --profile umber-cloud-auditor
python checks/run_all.py --profile umber-cloud-auditor
```

What `SecurityAudit` can do: read configurations (bucket settings, security
groups, IAM metadata). What it cannot do: read your data, create, modify, or
delete anything.

## Option B — cross-account IAM role (the product path, no long-lived keys)

Instead of access keys, you create a role in YOUR account that Umber Cloud's
account is allowed to assume, protected by an external ID (prevents the
confused-deputy attack). Revoke access anytime by deleting the role.

1. IAM → **Roles** → **Create role** → **Custom trust policy**, paste:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::UMBER_CLOUD_ACCOUNT_ID:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "YOUR_UNIQUE_EXTERNAL_ID" }
      }
    }
  ]
}
```

2. Attach the AWS-managed **SecurityAudit** policy → name the role
   `UmberCloudAudit` → Create role
3. Give Umber Cloud the role ARN (`arn:aws:iam::YOUR_ACCOUNT:role/UmberCloudAudit`)
   and your external ID

`UMBER_CLOUD_ACCOUNT_ID` and the external ID are issued during signup.
(Pre-launch note: this is the onboarding flow the dashboard will automate —
generate external ID per customer, render this trust policy pre-filled, verify
the role with one `sts:AssumeRole` call.)

## What we scan (and what we never touch)

| We read | We never |
|---------|----------|
| Bucket public-access settings, ACL grants, policy statements | Read objects inside buckets |
| Security group rules | Touch instances or traffic |
| IAM account summary, key ages, policy documents | Create/change/delete anything |
| CloudTrail and encryption configuration | See application data |

Revoke access anytime: delete the IAM user (Option A) or the role (Option B).
