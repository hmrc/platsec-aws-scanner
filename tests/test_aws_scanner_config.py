from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import mock_open, patch

import os

from src.data.aws_organizations_types import Account
from src.aws_scanner_config import AwsScannerConfig


class TestAwsScannerConfig(AwsScannerTestCase):
    def test_init_config_from_file(self) -> None:
        aws_scanner_config = AwsScannerConfig()
        self.assertEqual(Account("555666777888", "athena"), aws_scanner_config.athena_account())
        self.assertEqual("athena_role", aws_scanner_config.athena_role())
        self.assertEqual("some_prefix", aws_scanner_config.athena_database_prefix())
        self.assertEqual("query-results-bucket", aws_scanner_config.athena_query_results_bucket())
        self.assertEqual("cloudtrail-logs-bucket", aws_scanner_config.cloudtrail_logs_bucket())
        self.assertEqual(90, aws_scanner_config.cloudtrail_logs_retention_days())
        self.assertEqual(Account("999888777666", "organization"), aws_scanner_config.organization_account())
        self.assertEqual("orgs_role", aws_scanner_config.organization_role())
        self.assertTrue(aws_scanner_config.organization_include_root_accounts())
        self.assertEqual("Parent OU", aws_scanner_config.organization_parent())
        self.assertEqual("stdout", aws_scanner_config.reports_output())
        self.assertEqual(Account("333222333222", "reports"), aws_scanner_config.reports_account())
        self.assertEqual("s3_reports_role", aws_scanner_config.reports_role())
        self.assertEqual("scanner-reports-bucket", aws_scanner_config.reports_bucket())
        self.assertEqual("s3_role", aws_scanner_config.s3_role())
        self.assertEqual(3600, aws_scanner_config.session_duration_seconds())
        self.assertEqual("ssm_role", aws_scanner_config.ssm_role())
        self.assertEqual(10, aws_scanner_config.tasks_executors())
        self.assertEqual(Account("111222333444", "user"), aws_scanner_config.user_account())
        self.assertEqual("joe.bloggs", aws_scanner_config.user_name())

    @patch.dict(
        os.environ,
        {
            "AWS_SCANNER_ATHENA_ACCOUNT": "888777666555",
            "AWS_SCANNER_ATHENA_ROLE": "the_athena_role",
            "AWS_SCANNER_ATHENA_DATABASE_PREFIX": "a_db_prefix",
            "AWS_SCANNER_ATHENA_QUERY_RESULTS_BUCKET": "a-query-results-bucket",
            "AWS_SCANNER_CLOUDTRAIL_LOGS_BUCKET": "a-cloudtrail-logs-bucket",
            "AWS_SCANNER_CLOUDTRAIL_LOGS_RETENTION_DAYS": "30",
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
        aws_scanner_config = AwsScannerConfig()
        self.assertEqual(Account("888777666555", "athena"), aws_scanner_config.athena_account())
        self.assertEqual("the_athena_role", aws_scanner_config.athena_role())
        self.assertEqual("a_db_prefix", aws_scanner_config.athena_database_prefix())
        self.assertEqual("a-query-results-bucket", aws_scanner_config.athena_query_results_bucket())
        self.assertEqual("a-cloudtrail-logs-bucket", aws_scanner_config.cloudtrail_logs_bucket())
        self.assertEqual(30, aws_scanner_config.cloudtrail_logs_retention_days())
        self.assertEqual(Account("666777888999", "organization"), aws_scanner_config.organization_account())
        self.assertEqual("the_orgs_role", aws_scanner_config.organization_role())
        self.assertFalse(aws_scanner_config.organization_include_root_accounts())
        self.assertEqual("The Parent OU", aws_scanner_config.organization_parent())
        self.assertEqual("s3", aws_scanner_config.reports_output())
        self.assertEqual(Account("565656565656", "reports"), aws_scanner_config.reports_account())
        self.assertEqual("the_s3_report_role", aws_scanner_config.reports_role())
        self.assertEqual("a-scanner-reports-bucket", aws_scanner_config.reports_bucket())
        self.assertEqual("the_s3_role", aws_scanner_config.s3_role())
        self.assertEqual(120, aws_scanner_config.session_duration_seconds())
        self.assertEqual("the_ssm_role", aws_scanner_config.ssm_role())
        self.assertEqual(5, aws_scanner_config.tasks_executors())
        self.assertEqual(Account("444333222111", "user"), aws_scanner_config.user_account())
        self.assertEqual("john.doo", aws_scanner_config.user_name())

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
