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

from checks import cloudtrail, iam_admin, root_mfa, s3_public, sg_open, stale_keys  # noqa: E402


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
