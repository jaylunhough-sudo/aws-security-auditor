# Check backlog

CIS AWS Foundations aligned. Build in order.

| # | Check | Status | Module |
|---|-------|--------|--------|
| 1 | S3 public access (ACL, policy, public access block) | done | `checks/s3_public.py` |
| 2 | Security group open to 0.0.0.0/0 | planned | `checks/sg_open.py` |
| 3 | Root account MFA disabled | planned | `checks/root_mfa.py` |
| 4 | IAM policy allows `*:*` admin access | planned | `checks/iam_admin.py` |
| 5 | CloudTrail disabled or not multi-region | planned | `checks/cloudtrail.py` |
| 6 | Access keys older than 90 days | planned | `checks/stale_keys.py` |
| 7 | EBS volumes unencrypted | planned | `checks/ebs_encryption.py` |
| 8 | RDS snapshot public | planned | `checks/rds_public.py` |
| 9 | EC2 IMDSv1 enabled | planned | `checks/imdsv1.py` |
| 10 | Lambda over-privileged execution role | planned | `checks/lambda_iam.py` |
