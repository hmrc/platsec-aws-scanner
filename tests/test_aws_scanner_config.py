from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import mock_open, patch

import os

from src.data.aws_organizations_types import Account
from src.aws_scanner_config import AwsScannerConfig


class TestAwsScannerConfig(AwsScannerTestCase):
    def test_init_config_from_file(self) -> None:
        config = AwsScannerConfig()
        self.assertEqual(Account("555666777888", "athena"), config.athena_account())
        self.assertEqual("athena_role", config.athena_role())
        self.assertEqual("cost_explorer_role", config.cost_explorer_role())
        self.assertEqual("some_prefix", config.athena_database_prefix())
        self.assertEqual("query-results-bucket", config.athena_query_results_bucket())
        self.assertEqual(1200, config.athena_run_query_timeout())
        self.assertEqual("cloudtrail-logs-bucket", config.cloudtrail_logs_bucket())
        self.assertEqual(90, config.cloudtrail_logs_retention_days())
        self.assertEqual("ec2_role", config.ec2_role())
        self.assertEqual("ACTIVE", config.ec2_flow_log_status())
        self.assertEqual("ALL", config.ec2_flow_log_traffic_type())
        self.assertEqual("${srcaddr} ${dstaddr}", config.ec2_flow_log_format())
        self.assertEqual("iam_role", config.iam_role())
        self.assertEqual("an_alias", config.kms_key_alias())
        self.assertEqual({"account": "1234"}, config.kms_key_policy_default_statement("1234"))
        self.assertEqual(
            {"account": "89", "log_group_name": "/vpc/flow_log", "region": "us"},
            config.kms_key_policy_log_group_statement("89", "us"),
        )
        self.assertEqual("kms_role", config.kms_role())
        self.assertEqual("/vpc/flow_log", config.logs_vpc_log_group_name())
        self.assertEqual("[version, account_id, interface_id]", config.logs_vpc_log_group_pattern())
        self.assertEqual("arn:aws:logs:::destination:central", config.logs_vpc_log_group_destination())
        self.assertEqual("vpc_flow_log_role", config.logs_vpc_log_group_delivery_role())
        self.assertEqual(
            {"Statement": [{"Action": "sts:AssumeRole"}]}, config.logs_vpc_log_group_delivery_role_assume_policy()
        )
        self.assertEqual(
            {"Statement": [{"Action": ["logs:PutLogEvents"], "Effect": "Allow"}]},
            config.logs_vpc_log_group_delivery_role_policy_document(),
        )
        self.assertEqual("logs_role", config.logs_role())
        self.assertEqual(Account("999888777666", "organization"), config.organization_account())
        self.assertEqual("orgs_role", config.organization_role())
        self.assertTrue(config.organization_include_root_accounts())
        self.assertEqual("Parent OU", config.organization_parent())
        self.assertEqual("stdout", config.reports_output())
        self.assertEqual(Account("333222333222", "reports"), config.reports_account())
        self.assertEqual("s3_reports_role", config.reports_role())
        self.assertEqual("scanner-reports-bucket", config.reports_bucket())
        self.assertEqual("s3_role", config.s3_role())
        self.assertEqual(3600, config.session_duration_seconds())
        self.assertEqual("ssm_role", config.ssm_role())
        self.assertEqual(10, config.tasks_executors())
        self.assertEqual(Account("111222333444", "user"), config.user_account())
        self.assertEqual("joe.bloggs", config.user_name())

    @patch.dict(
        os.environ,
        {
            "AWS_SCANNER_ATHENA_ACCOUNT": "888777666555",
            "AWS_SCANNER_ATHENA_ROLE": "the_athena_role",
            "AWS_SCANNER_ATHENA_DATABASE_PREFIX": "a_db_prefix",
            "AWS_SCANNER_ATHENA_QUERY_RESULTS_BUCKET": "a-query-results-bucket",
            "AWS_SCANNER_ATHENA_RUN_QUERY_TIMEOUT": "900",
            "AWS_SCANNER_CLOUDTRAIL_LOGS_BUCKET": "a-cloudtrail-logs-bucket",
            "AWS_SCANNER_CLOUDTRAIL_LOGS_RETENTION_DAYS": "30",
            "AWS_SCANNER_EC2_ROLE": "the_ec2_role",
            "AWS_SCANNER_EC2_FLOW_LOG_STATUS": "FL_STATUS",
            "AWS_SCANNER_EC2_FLOW_LOG_TRAFFIC_TYPE": "ACCEPT",
            "AWS_SCANNER_EC2_FLOW_LOG_FORMAT": "${srcaddr}",
            "AWS_SCANNER_IAM_ROLE": "the_iam_role",
            "AWS_SCANNER_KMS_KEY_POLICY_DEFAULT_STATEMENT": '{"arn": ":$account_id:"}',
            "AWS_SCANNER_KMS_KEY_POLICY_LOG_GROUP_STATEMENT": '{"region": "$region-west-1"}',
            "AWS_SCANNER_KMS_KEY_ALIAS": "the_kms_key_alias",
            "AWS_SCANNER_KMS_ROLE": "the_kms_role",
            "AWS_SCANNER_LOGS_VPC_LOG_GROUP_NAME": "/vpc/central_flow_log_name",
            "AWS_SCANNER_LOGS_VPC_LOG_GROUP_PATTERN": "[version, account_id]",
            "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DESTINATION": "arn:aws:logs:::destination:some-central",
            "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE": "the_flow_log_delivery_role",
            "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_ASSUME_POLICY": '{"Statement": [{"Action": "s3:something"}]}',
            "AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_POLICY_DOCUMENT": '{"Statement": [{"Action": ["sts:hi"]}]}',
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
    def test_init_config_from_env_vars(self) -> None:
        config = AwsScannerConfig()
        self.assertEqual(Account("888777666555", "athena"), config.athena_account())
        self.assertEqual("the_athena_role", config.athena_role())
        self.assertEqual("a_db_prefix", config.athena_database_prefix())
        self.assertEqual("a-query-results-bucket", config.athena_query_results_bucket())
        self.assertEqual(900, config.athena_run_query_timeout())
        self.assertEqual("a-cloudtrail-logs-bucket", config.cloudtrail_logs_bucket())
        self.assertEqual(30, config.cloudtrail_logs_retention_days())
        self.assertEqual("the_ec2_role", config.ec2_role())
        self.assertEqual("FL_STATUS", config.ec2_flow_log_status())
        self.assertEqual("ACCEPT", config.ec2_flow_log_traffic_type())
        self.assertEqual("${srcaddr}", config.ec2_flow_log_format())
        self.assertEqual("the_iam_role", config.iam_role())
        self.assertEqual({"arn": ":0:"}, config.kms_key_policy_default_statement("0"))
        self.assertEqual({"region": "eu-west-1"}, config.kms_key_policy_log_group_statement("9", "eu"))
        self.assertEqual("the_kms_key_alias", config.kms_key_alias())
        self.assertEqual("the_kms_role", config.kms_role())
        self.assertEqual("/vpc/central_flow_log_name", config.logs_vpc_log_group_name())
        self.assertEqual("[version, account_id]", config.logs_vpc_log_group_pattern())
        self.assertEqual("arn:aws:logs:::destination:some-central", config.logs_vpc_log_group_destination())
        self.assertEqual("the_flow_log_delivery_role", config.logs_vpc_log_group_delivery_role())
        self.assertEqual(
            {"Statement": [{"Action": "s3:something"}]}, config.logs_vpc_log_group_delivery_role_assume_policy()
        )
        self.assertEqual(
            {"Statement": [{"Action": ["sts:hi"]}]}, config.logs_vpc_log_group_delivery_role_policy_document()
        )
        self.assertEqual("some_logs_role", config.logs_role())
        self.assertEqual(Account("666777888999", "organization"), config.organization_account())
        self.assertEqual("the_orgs_role", config.organization_role())
        self.assertFalse(config.organization_include_root_accounts())
        self.assertEqual("The Parent OU", config.organization_parent())
        self.assertEqual("s3", config.reports_output())
        self.assertEqual(Account("565656565656", "reports"), config.reports_account())
        self.assertEqual("the_s3_report_role", config.reports_role())
        self.assertEqual("a-scanner-reports-bucket", config.reports_bucket())
        self.assertEqual("the_s3_role", config.s3_role())
        self.assertEqual(120, config.session_duration_seconds())
        self.assertEqual("the_ssm_role", config.ssm_role())
        self.assertEqual(5, config.tasks_executors())
        self.assertEqual(Account("444333222111", "user"), config.user_account())
        self.assertEqual("john.doo", config.user_name())

    def test_config_not_found(self) -> None:
        with patch("builtins.open", mock_open(read_data="")):
            with self.assertRaisesRegex(SystemExit, "missing config: section 'user', key 'account'"):
                AwsScannerConfig().user_account()

    def test_config_file_is_missing(self) -> None:
        with patch("configparser.ConfigParser.read", return_value=[]):
            with self.assertLogs("AwsScannerConfig", level="DEBUG") as info_log:
                AwsScannerConfig()
        self.assertIn("Config file 'aws_scanner_config.ini' not found", info_log.output[0])

    @patch.dict(os.environ, {"AWS_SCANNER_REPORTS_OUTPUT": "wat"}, clear=True)
    def test_unsupported_reports_output(self) -> None:
        with self.assertRaisesRegex(SystemExit, "unsupported config: section 'reports', key 'output'"):
            AwsScannerConfig().reports_output()

    @patch.dict(os.environ, {"AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_ASSUME_POLICY": "{"}, clear=True)
    def test_invalid_format_logs_vpc_log_group_delivery_role_assume_policy(self) -> None:
        with self.assertRaisesRegex(SystemExit, "vpc_log_group_delivery_role_assume_policy"):
            AwsScannerConfig().logs_vpc_log_group_delivery_role_assume_policy()

    @patch.dict(os.environ, {"AWS_SCANNER_LOGS_VPC_LOG_GROUP_DELIVERY_ROLE_POLICY_DOCUMENT": "}"}, clear=True)
    def test_invalid_format_logs_vpc_log_group_delivery_role_policy_document(self) -> None:
        with self.assertRaisesRegex(SystemExit, "vpc_log_group_delivery_role_policy_document"):
            AwsScannerConfig().logs_vpc_log_group_delivery_role_policy_document()

    @patch.dict(os.environ, {"AWS_SCANNER_KMS_KEY_POLICY_DEFAULT_STATEMENT": "$1"}, clear=True)
    def test_invalid_templated_config(self) -> None:
        with self.assertRaisesRegex(SystemExit, "key_policy_default_statement"):
            AwsScannerConfig().kms_key_policy_default_statement("1")

    @patch.dict(os.environ, {"AWS_SCANNER_KMS_KEY_POLICY_LOG_GROUP_STATEMENT": "$missing"}, clear=True)
    def test_templated_config_missing_keyword(self) -> None:
        with self.assertRaisesRegex(SystemExit, "key_policy_log_group_statement"):
            AwsScannerConfig().kms_key_policy_log_group_statement("1", "us")
