"""Offline tests for all checks using moto — no live AWS needed.

Run: pytest
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from checks import (  # noqa: E402
    cloudtrail,
    ebs_encryption,
    iam_admin,
    imdsv1,
    lambda_iam,
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
