"""Offline tests for all checks using moto — no live AWS needed.

Run: pytest
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from checks import (  # noqa: E402
    agent_keys,
    ai_agent_roles,
    cloudtrail,
    ebs_encryption,
    iam_admin,
    imdsv1,
    lambda_iam,
    lambda_secrets,
    rds_public,
    root_mfa,
    s3_public,
    sg_open,
    stale_keys,
)


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


# --- UC-001 S3 public access -------------------------------------------------


@mock_aws
def test_s3_flags_bucket_without_public_access_block():
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="exposed-bucket")

    findings = s3_public.run_check(region="us-east-1")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == "UC-001"
    assert finding.status == "fail"
    assert "public access block" in finding.detection.lower()
    assert finding.plain_english_risk  # three-output standard
    assert "put-public-access-block" in finding.fix_cli
    assert "aws_s3_bucket_public_access_block" in finding.fix_terraform
    assert "CC6.6" in finding.soc2_refs


@mock_aws
def test_s3_passes_locked_down_bucket():
    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="locked-bucket")
    client.put_public_access_block(
        Bucket="locked-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    findings = s3_public.run_check(region="us-east-1")

    assert len(findings) == 1
    assert findings[0].status == "pass"
    assert findings[0].plain_english_risk == ""


# --- UC-002 Security groups --------------------------------------------------


@mock_aws
def test_sg_flags_ssh_open_to_world():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName="test-open", Description="test", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = sg_open.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    finding = fails[0]
    assert finding.check_id == "UC-002"
    assert "22" in finding.detection
    assert "SSH" in finding.plain_english_risk
    assert "revoke-security-group-ingress" in finding.fix_cli


@mock_aws
def test_sg_ignores_https_open_to_world():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName="test-web", Description="test", VpcId=vpc
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    findings = sg_open.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail" and "test-web" in f.resource]

    assert fails == []  # 443 to the world is normal for websites — no noise


# --- UC-003 Root MFA ----------------------------------------------------------


@mock_aws
def test_root_mfa_reports_two_controls():
    findings = root_mfa.run_check(region="us-east-1")

    assert len(findings) == 2
    ids = {f.check_id for f in findings}
    assert ids == {"UC-003", "UC-003b"}
    for finding in findings:
        assert finding.status in ("pass", "fail")
        if finding.status == "fail":
            assert finding.plain_english_risk
            assert finding.fix_cli


# --- UC-004 IAM full admin -----------------------------------------------------


@mock_aws
def test_iam_admin_flags_star_star_policy():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_policy(
        PolicyName="danger-admin",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Action": "*", "Resource": "*"}]}',
    )

    findings = iam_admin.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "danger-admin" in fails[0].resource
    assert fails[0].plain_english_risk
    assert "list-entities-for-policy" in fails[0].fix_cli


@mock_aws
def test_iam_admin_passes_scoped_policy():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_policy(
        PolicyName="scoped-read",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Action": "s3:GetObject", "Resource": "arn:aws:s3:::x/*"}]}',
    )

    findings = iam_admin.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-005 CloudTrail ----------------------------------------------------------


@mock_aws
def test_cloudtrail_fails_with_no_trails():
    findings = cloudtrail.run_check(region="us-east-1")

    assert len(findings) == 1
    assert findings[0].status == "fail"
    assert "No CloudTrail" in findings[0].detection
    assert "create-trail" in findings[0].fix_cli


# --- UC-006 Stale keys ----------------------------------------------------------


@mock_aws
def test_stale_keys_passes_with_fresh_key():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="dev")
    iam.create_access_key(UserName="dev")  # created "now" — not stale

    findings = stale_keys.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-007 EBS encryption -------------------------------------------------------


@mock_aws
def test_ebs_flags_unencrypted_volume_and_default_off():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)

    findings = ebs_encryption.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    # default-encryption off + the unencrypted volume
    assert len(fails) == 2
    volume_fail = next(f for f in fails if f.check_name == "Unencrypted EBS volume")
    assert "create-snapshot" in volume_fail.fix_cli
    assert "CC6.7" in volume_fail.soc2_refs


@mock_aws
def test_ebs_passes_encrypted_volume():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.enable_ebs_encryption_by_default()
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)

    findings = ebs_encryption.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-008 RDS public -----------------------------------------------------------


@mock_aws
def test_rds_flags_public_instance():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="testing-only",
        AllocatedStorage=20,
        PubliclyAccessible=True,
    )

    findings = rds_public.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "public-db" in fails[0].resource
    assert fails[0].severity == "critical"
    assert "no-publicly-accessible" in fails[0].fix_cli


@mock_aws
def test_rds_passes_private_instance():
    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="private-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="testing-only",
        AllocatedStorage=20,
        PubliclyAccessible=False,
    )

    findings = rds_public.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-009 IMDSv1 ---------------------------------------------------------------


@mock_aws
def test_imdsv1_flags_optional_tokens():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        MetadataOptions={"HttpTokens": "optional"},
    )

    findings = imdsv1.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "modify-instance-metadata-options" in fails[0].fix_cli


@mock_aws
def test_imdsv1_passes_required_tokens():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.run_instances(
        ImageId="ami-12345678", MinCount=1, MaxCount=1,
        MetadataOptions={"HttpTokens": "required"},
    )

    findings = imdsv1.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-010 Lambda over-privileged roles ------------------------------------------


def _make_lambda_with_role(admin: bool = False):
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="fn-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": '
        '"Allow", "Principal": {"Service": "lambda.amazonaws.com"}, '
        '"Action": "sts:AssumeRole"}]}',
    )["Role"]
    if admin:
        # moto doesn't preload AWS-managed policies, so exercise the same
        # *:* detection through a customer-managed policy
        arn = iam.create_policy(
            PolicyName="do-everything",
            PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": '
            '"Allow", "Action": "*", "Resource": "*"}]}',
        )["Policy"]["Arn"]
        iam.attach_role_policy(RoleName="fn-role", PolicyArn=arn)
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="fn",
        Runtime="python3.12",
        Role=role["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"fake code"},
    )


@mock_aws
def test_lambda_flags_admin_role():
    _make_lambda_with_role(admin=True)

    findings = lambda_iam.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "do-everything" in fails[0].detection
    assert "detach-role-policy" in fails[0].fix_cli


@mock_aws
def test_lambda_passes_plain_role():
    _make_lambda_with_role()

    findings = lambda_iam.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-020 AI/agent roles ---------------------------------------------------------


BEDROCK_TRUST = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": '
    '{"Service": "bedrock.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
)
STAR_STAR = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
    '"Action": "*", "Resource": "*"}]}'
)


@mock_aws
def test_ai_role_flags_bedrock_role_with_admin():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="support-agent-role", AssumeRolePolicyDocument=BEDROCK_TRUST)
    arn = iam.create_policy(PolicyName="agent-admin", PolicyDocument=STAR_STAR)["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="support-agent-role", PolicyArn=arn)

    findings = ai_agent_roles.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "support-agent-role" in fails[0].resource
    assert fails[0].severity == "critical"
    assert "bedrock.amazonaws.com" in fails[0].detection


@mock_aws
def test_ai_role_passes_scoped_bedrock_role():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_role(RoleName="chatbot-role", AssumeRolePolicyDocument=BEDROCK_TRUST)

    findings = ai_agent_roles.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)
    assert "1 identified" in findings[0].resource


# --- UC-021 Machine identities on static keys ---------------------------------------


@mock_aws
def test_agent_keys_flags_bot_user_with_active_key():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="n8n-automation-bot")
    iam.create_access_key(UserName="n8n-automation-bot")

    findings = agent_keys.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "n8n-automation-bot" in fails[0].resource
    assert "update-access-key" in fails[0].fix_cli


@mock_aws
def test_agent_keys_ignores_human_user():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="jaylun")
    iam.create_access_key(UserName="jaylun")

    findings = agent_keys.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- UC-022 Secrets in Lambda env vars ----------------------------------------------


def _make_lambda_with_env(env_vars):
    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="env-fn-role",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": '
        '"Allow", "Principal": {"Service": "lambda.amazonaws.com"}, '
        '"Action": "sts:AssumeRole"}]}',
    )["Role"]
    lam = boto3.client("lambda", region_name="us-east-1")
    lam.create_function(
        FunctionName="env-fn",
        Runtime="python3.12",
        Role=role["Arn"],
        Handler="index.handler",
        Code={"ZipFile": b"fake code"},
        Environment={"Variables": env_vars},
    )


@mock_aws
def test_lambda_secrets_flags_api_key_env_var():
    _make_lambda_with_env({"OPENAI_API_KEY": "sk-abc123", "LOG_LEVEL": "info"})

    findings = lambda_secrets.run_check(region="us-east-1")
    fails = [f for f in findings if f.status == "fail"]

    assert len(fails) == 1
    assert "OPENAI_API_KEY" in fails[0].detection
    assert "sk-abc123" not in fails[0].detection  # never leak the value
    assert "secretsmanager" in fails[0].fix_cli


@mock_aws
def test_lambda_secrets_passes_clean_env():
    _make_lambda_with_env({"LOG_LEVEL": "info", "STAGE": "prod"})

    findings = lambda_secrets.run_check(region="us-east-1")

    assert all(f.status == "pass" for f in findings)


# --- Cross-account (concierge scan path) ------------------------------------------


@mock_aws
def test_cross_account_temporary_credentials_flow():
    from checks.cross_account import customer_account_id, temporary_credentials

    iam = boto3.client("iam", region_name="us-east-1")
    role = iam.create_role(
        RoleName="UmberCloudAudit",
        AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": '
        '"Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}',
    )["Role"]

    with temporary_credentials(role["Arn"], external_id="test-ext-id") as response:
        assert "Credentials" in response
        # checks must work inside the block using the assumed credentials
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="customer-bucket")
        findings = s3_public.run_check(region="us-east-1")
        assert any("customer-bucket" in f.resource for f in findings)

    assert customer_account_id(role["Arn"]) == role["Arn"].split(":")[4]


def test_trust_policy_contains_external_id():
    import generate_onboarding

    policy = generate_onboarding.trust_policy("111122223333", "my-external-id")
    statement = policy["Statement"][0]

    assert statement["Principal"]["AWS"] == "arn:aws:iam::111122223333:root"
    assert statement["Condition"]["StringEquals"]["sts:ExternalId"] == "my-external-id"


# --- Evidence export (PDF) ----------------------------------------------------------


def test_export_produces_pdf(tmp_path, monkeypatch):
    import export_evidence

    scan = {
        "scanned_at_utc": "2026-07-02T00:00:00+00:00",
        "score": 92,
        "summary": {"total": 1, "pass": 1, "fail": 0},
        "findings": [
            {
                "check_id": "UC-001",
                "check_name": "S3 public access",
                "resource": "s3://demo",
                "region": "us-east-1",
                "severity": "critical",
                "status": "pass",
                "detection": "No public access indicators found",
                "plain_english_risk": "",
                "fix_terraform": "",
                "fix_cli": "",
                "cis_refs": ["2.1.1"],
                "soc2_refs": ["CC6.1"],
            }
        ],
    }
    scan_path = tmp_path / "2026-07-02T000000.json"
    scan_path.write_text(json.dumps(scan))
    monkeypatch.setattr(export_evidence, "EVIDENCE_DIR", tmp_path / "evidence")

    csv_path, md_path, pdf_path = export_evidence.export(scan_path)

    assert csv_path.exists()
    assert md_path.exists()
    assert pdf_path.exists()
    assert pdf_path.read_bytes()[:4] == b"%PDF"
