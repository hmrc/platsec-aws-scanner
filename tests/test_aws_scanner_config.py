from unittest.mock import mock_open, patch
import pytest
import logging
from typing import Any

import os

from src.aws_scanner_config import AwsScannerConfig
from src.clients.aws_s3_client import AwsS3Client
from src.data.aws_organizations_types import Account


def test_init_config_from_file() -> None:
    config = AwsScannerConfig()
    assert Account("555666777888", "athena") == config.athena_account()
    assert "some_prefix" == config.athena_database_prefix()
    assert "the-flow-logs-bucket" == config.athena_flow_logs_bucket()
    assert "cost_explorer_role" == config.cost_explorer_role()
    assert "query-results-bucket" == config.athena_query_results_bucket()
    assert "athena_role" == config.athena_role()
    assert Account("111344576685", "cloudtrail") == config.cloudtrail_account()
    assert "74356589" == config.cloudtrail_event_key_id()
    assert "the-cloudtrail-log-group" == config.cloudtrail_log_group_name()
    assert "cloudtrail-logs-bucket" == config.cloudtrail_logs_bucket()
    assert 90 == config.cloudtrail_logs_retention_days()
    assert "cloudtrail_role" == config.cloudtrail_role()
    assert 0 == config.athena_query_results_polling_delay_seconds()
    assert 1200 == config.athena_query_timeout_seconds()
    assert 0 == config.athena_query_throttling_seconds()
    assert "ec2_role" == config.ec2_role()
    assert "ACTIVE" == config.ec2_flow_log_status()
    assert "ALL" == config.ec2_flow_log_traffic_type()
    assert "${srcaddr} ${dstaddr}" == config.ec2_flow_log_format()
    assert "iam_role" == config.iam_role()
    assert "iam_audit_role" == config.iam_audit_role()
    assert 8 == config.iam_password_policy_minimum_password_length()
    assert config.iam_password_policy_require_symbols()
    assert config.iam_password_policy_require_numbers()
    assert not config.iam_password_policy_require_uppercase_chars()
    assert not config.iam_password_policy_require_lowercase_chars()
    assert not config.iam_password_policy_allow_users_to_change_password()
    assert 90 == config.iam_password_policy_max_password_age()
    assert 12 == config.iam_password_policy_password_reuse_prevention()
    assert not config.iam_password_policy_hard_expiry()
    assert "kms_role" == config.kms_role()
    assert "/vpc/flow_log" == config.logs_vpc_log_group_name()
    assert "[version, account_id, interface_id]" == config.logs_vpc_log_group_pattern()
    assert "arn:aws:logs:::destination:central" == config.logs_vpc_log_group_destination()
    assert "vpc_flow_log_role" == config.logs_vpc_log_group_delivery_role()
    assert {"Statement": [{"Action": "sts:AssumeRole"}]} == config.logs_vpc_log_group_delivery_role_assume_policy()
    assert {
        "Statement": [{"Action": ["logs:*"], "Effect": "Allow", "Resource": "*"}]
    } == config.logs_vpc_log_group_delivery_role_policy_document()
    assert 14 == config.logs_vpc_log_group_retention_policy_days()
    assert "logs_role" == config.logs_role()
    assert Account("999888777666", "organization") == config.organization_account()
    assert "orgs_role" == config.organization_role()
    assert config.organization_include_root_accounts()
    assert "Parent OU" == config.organization_parent()
    assert "stdout" == config.reports_output()
    assert Account("333222333222", "reports") == config.reports_account()
    assert "s3_reports_role" == config.reports_role()
    assert "scanner-reports-bucket", config.reports_bucket()
    assert "s3_role" == config.s3_role()
    assert 3600 == config.session_duration_seconds()
    assert "ssm_role" == config.ssm_role()
    assert 10 == config.tasks_executors()
    assert Account("111222333444", "user") == config.user_account()
    assert "joe.bloggs" == config.user_name()


@patch.dict(
    os.environ,
    {
        "AWS_SCANNER_ATHENA_ACCOUNT": "888777666555",
        "AWS_SCANNER_ATHENA_DATABASE_PREFIX": "a_db_prefix",
        "AWS_SCANNER_ATHENA_FLOW_LOGS_BUCKET": "a-flow-logs-bucket",
        "AWS_SCANNER_ATHENA_QUERY_RESULTS_BUCKET": "a-query-results-bucket",
        "AWS_SCANNER_ATHENA_QUERY_RESULTS_POLLING_DELAY_SECONDS": "2",
        "AWS_SCANNER_ATHENA_QUERY_TIMEOUT_SECONDS": "900",
        "AWS_SCANNER_ATHENA_QUERY_THROTTLING_SECONDS": "3",
        "AWS_SCANNER_ATHENA_ROLE": "the_athena_role",
        "AWS_SCANNER_CLOUDTRAIL_ACCOUNT": "464878555331",
        "AWS_SCANNER_CLOUDTRAIL_EVENT_KEY_ID": "9874565",
        "AWS_SCANNER_CLOUDTRAIL_LOG_GROUP_NAME": "a_log_group_name",
        "AWS_SCANNER_CLOUDTRAIL_LOGS_BUCKET": "a-cloudtrail-logs-bucket",
        "AWS_SCANNER_CLOUDTRAIL_ROLE": "a_cloudtrail_role",
        "AWS_SCANNER_CLOUDTRAIL_LOGS_RETENTION_DAYS": "30",
        "AWS_SCANNER_EC2_ROLE": "the_ec2_role",
        "AWS_SCANNER_EC2_FLOW_LOG_STATUS": "FL_STATUS",
        "AWS_SCANNER_EC2_FLOW_LOG_TRAFFIC_TYPE": "ACCEPT",
        "AWS_SCANNER_EC2_FLOW_LOG_FORMAT": "${srcaddr}",
        "AWS_SCANNER_IAM_ROLE": "the_iam_role",
        "AWS_SCANNER_IAM_AUDIT_ROLE": "the_iam_audit_role",
        "AWS_SCANNER_KMS_ROLE": "the_kms_role",
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_NAME": "/vpc/central_flow_log_name",
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_PATTERN": "[version, account_id]",
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DESTINATION": "arn:aws:logs:::destination:some-central",
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE": "the_flow_log_delivery_role",
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_ASSUME_POLICY": '{"Statement": [{"Action": "s3:something"}]}',
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_POLICY_DOCUMENT": '{"Statement": [{"Action": ["sts:hi"]}]}',
        "AWS_SCANNER_LOGS_VPC_LOG_GROUP_RETENTION_POLICY_DAYS": "21",
        "AWS_SCANNER_LOGS_ROLE": "some_logs_role",
        "AWS_SCANNER_ORGANIZATION_ACCOUNT": "666777888999",
        "AWS_SCANNER_ORGANIZATION_ROLE": "the_orgs_role",
        "AWS_SCANNER_ORGANIZATION_INCLUDE_ROOT_ACCOUNTS": "false",
        "AWS_SCANNER_ORGANIZATION_PARENT": "The Parent OU",
        "AWS_SCANNER_REPORTS_OUTPUT": "s3",
        "AWS_SCANNER_REPORTS_ACCOUNT": "565656565656",
        "AWS_SCANNER_REPORTS_ROLE": "the_s3_report_role",
        "AWS_SCANNER_REPORTS_BUCKET": "a-scanner-reports-bucket",
        "AWS_SCANNER_S3_ROLE": "the_s3_role",
        "AWS_SCANNER_SESSION_DURATION_SECONDS": "120",
        "AWS_SCANNER_SSM_ROLE": "the_ssm_role",
        "AWS_SCANNER_TASKS_EXECUTORS": "5",
        "AWS_SCANNER_USER_ACCOUNT": "444333222111",
        "AWS_SCANNER_USER_NAME": "john.doo",
    },
    clear=True,
)
def test_init_config_from_env_vars() -> None:
    config = AwsScannerConfig()
    assert Account("888777666555", "athena") == config.athena_account()
    assert "a_db_prefix" == config.athena_database_prefix()
    assert "a-flow-logs-bucket" == config.athena_flow_logs_bucket()
    assert "a-query-results-bucket" == config.athena_query_results_bucket()
    assert 2 == config.athena_query_results_polling_delay_seconds()
    assert 900 == config.athena_query_timeout_seconds()
    assert 3 == config.athena_query_throttling_seconds()
    assert "the_athena_role" == config.athena_role()
    assert Account("464878555331", "cloudtrail") == config.cloudtrail_account()
    assert "9874565" == config.cloudtrail_event_key_id()
    assert "a_log_group_name" == config.cloudtrail_log_group_name()
    assert "a-cloudtrail-logs-bucket" == config.cloudtrail_logs_bucket()
    assert 30 == config.cloudtrail_logs_retention_days()
    assert "a_cloudtrail_role" == config.cloudtrail_role()
    assert "the_ec2_role" == config.ec2_role()
    assert "FL_STATUS" == config.ec2_flow_log_status()
    assert "ACCEPT" == config.ec2_flow_log_traffic_type()
    assert "${srcaddr}" == config.ec2_flow_log_format()
    assert "the_iam_role" == config.iam_role()
    assert "the_iam_audit_role" == config.iam_audit_role()
    assert "the_kms_role" == config.kms_role()
    assert "/vpc/central_flow_log_name" == config.logs_vpc_log_group_name()
    assert "[version, account_id]" == config.logs_vpc_log_group_pattern()
    assert "arn:aws:logs:::destination:some-central" == config.logs_vpc_log_group_destination()
    assert "the_flow_log_delivery_role" == config.logs_vpc_log_group_delivery_role()
    assert {"Statement": [{"Action": "s3:something"}]} == config.logs_vpc_log_group_delivery_role_assume_policy()
    assert {"Statement": [{"Action": ["sts:hi"]}]} == config.logs_vpc_log_group_delivery_role_policy_document()
    assert 21 == config.logs_vpc_log_group_retention_policy_days()
    assert "some_logs_role" == config.logs_role()
    assert Account("666777888999", "organization") == config.organization_account()
    assert "the_orgs_role" == config.organization_role()
    assert not config.organization_include_root_accounts()
    assert "The Parent OU" == config.organization_parent()
    assert "s3" == config.reports_output()
    assert Account("565656565656", "reports") == config.reports_account()
    assert "the_s3_report_role" == config.reports_role()
    assert "a-scanner-reports-bucket" == config.reports_bucket()
    assert "the_s3_role" == config.s3_role()
    assert 120 == config.session_duration_seconds()
    assert "the_ssm_role" == config.ssm_role()
    assert 5 == config.tasks_executors()
    assert Account("444333222111", "user") == config.user_account()
    assert "john.doo" == config.user_name()


def test_config_not_found() -> None:
    with patch("builtins.open", mock_open(read_data="")):
        with pytest.raises(SystemExit, match="missing config: section 'user', key 'account'"):
            AwsScannerConfig().user_account()


def test_config_file_is_missing(caplog: Any) -> None:
    with patch("configparser.ConfigParser.read", return_value=[]):
        with caplog.at_level(logging.DEBUG):
            AwsScannerConfig()
    assert "Config file 'aws_scanner_test_config.ini' not found" in caplog.text


@patch.dict(os.environ, {"AWS_SCANNER_REPORTS_OUTPUT": "wat"}, clear=True)
def test_unsupported_reports_output() -> None:
    with pytest.raises(SystemExit, match="unsupported config: section 'reports', key 'output'"):
        AwsScannerConfig().reports_output()


@patch.dict(os.environ, {"AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_ASSUME_POLICY": "{"}, clear=True)
def test_invalid_format_logs_vpc_log_group_delivery_role_assume_policy() -> None:
    with pytest.raises(SystemExit, match="vpc_log_group_delivery_role_assume_policy"):
        AwsScannerConfig().logs_vpc_log_group_delivery_role_assume_policy()


@patch.dict(os.environ, {"AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_POLICY_DOCUMENT": "}"})
def test_invalid_format_logs_vpc_log_group_delivery_role_policy_document() -> None:
    with pytest.raises(SystemExit, match="vpc_log_group_delivery_role_policy_document"):
        AwsScannerConfig().logs_vpc_log_group_delivery_role_policy_document()


@patch.dict(os.environ, {"AWS_SCANNER_ATHENA_QUERY_TIMEOUT_SECONDS": "bonjour"})
def test_invalid_type_for_int_config_item() -> None:
    with pytest.raises(SystemExit):
        AwsScannerConfig().athena_query_timeout_seconds()


@patch.dict(os.environ, {"AWS_SCANNER_CONFIG_BUCKET": "conf-buck"})
def test_load_config_from_s3() -> None:
    conf = "[iam]\nrole = TheIamRole"
    with patch.object(
        AwsS3Client,
        "get_object",
        side_effect=lambda b, k: conf if b == "conf-buck" and k == "aws_scanner_config.ini" else None,
    ):
        assert AwsScannerConfig().iam_role() == "TheIamRole"
