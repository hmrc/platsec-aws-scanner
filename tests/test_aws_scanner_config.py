from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import mock_open, patch

import os

from src.data.aws_organizations_types import Account
from src.aws_scanner_config import AwsScannerConfig


class TestAwsScannerConfig(AwsScannerTestCase):
    def test_init_config_from_file(self) -> None:
        aws_scanner_config = AwsScannerConfig()
        self.assertEqual(Account("111222333444", "auth"), aws_scanner_config.account_auth())
        self.assertEqual(Account("555666777888", "cloudtrail"), aws_scanner_config.account_cloudtrail())
        self.assertEqual(Account("999888777666", "root"), aws_scanner_config.account_root())
        self.assertEqual("some_prefix", aws_scanner_config.athena_database_prefix())
        self.assertEqual("query-results-bucket", aws_scanner_config.bucket_athena_query_results())
        self.assertEqual("cloudtrail-logs-bucket", aws_scanner_config.bucket_cloudtrail_logs())
        self.assertEqual(90, aws_scanner_config.cloudtrail_log_retention_days())
        self.assertTrue(aws_scanner_config.org_unit_include_root_accounts())
        self.assertEqual("Parent OU", aws_scanner_config.org_unit_parent())
        self.assertEqual("cloudtrail_role", aws_scanner_config.role_cloudtrail())
        self.assertEqual("orgs_role", aws_scanner_config.role_organizations())
        self.assertEqual("s3_role", aws_scanner_config.role_s3())
        self.assertEqual("ssm_role", aws_scanner_config.role_ssm())
        self.assertEqual(3600, aws_scanner_config.session_duration_seconds())
        self.assertEqual(10, aws_scanner_config.tasks_executor())
        self.assertEqual("joe.bloggs", aws_scanner_config.username())

    @patch.dict(
        os.environ,
        {
            "AWS_SCANNER_ACCOUNTS_AUTH": "444333222111",
            "AWS_SCANNER_ACCOUNTS_CLOUDTRAIL": "888777666555",
            "AWS_SCANNER_ACCOUNTS_ROOT": "666777888999",
            "AWS_SCANNER_ATHENA_DATABASE_PREFIX": "a_db_prefix",
            "AWS_SCANNER_BUCKETS_ATHENA_QUERY_RESULTS": "a-query-results-bucket",
            "AWS_SCANNER_BUCKETS_CLOUDTRAIL_LOGS": "a-cloudtrail-logs-bucket",
            "AWS_SCANNER_CLOUDTRAIL_LOG_RETENTION_DAYS": "30",
            "AWS_SCANNER_ORGANIZATIONAL_UNIT_INCLUDE_ROOT_ACCOUNTS": "false",
            "AWS_SCANNER_ORGANIZATIONAL_UNIT_PARENT": "The Parent OU",
            "AWS_SCANNER_ROLES_CLOUDTRAIL": "the_cloudtrail_role",
            "AWS_SCANNER_ROLES_ORGANIZATIONS": "the_orgs_role",
            "AWS_SCANNER_ROLES_S3": "the_s3_role",
            "AWS_SCANNER_ROLES_SSM": "the_ssm_role",
            "AWS_SCANNER_SESSION_DURATION_SECONDS": "120",
            "AWS_SCANNER_TASKS_EXECUTOR": "5",
            "AWS_SCANNER_ROLES_USERNAME": "john.doo",
        },
        clear=True,
    )
    def test_init_config_from_env_vars(self) -> None:
        aws_scanner_config = AwsScannerConfig()
        self.assertEqual(Account("444333222111", "auth"), aws_scanner_config.account_auth())
        self.assertEqual(Account("888777666555", "cloudtrail"), aws_scanner_config.account_cloudtrail())
        self.assertEqual(Account("666777888999", "root"), aws_scanner_config.account_root())
        self.assertEqual("a_db_prefix", aws_scanner_config.athena_database_prefix())
        self.assertEqual("a-query-results-bucket", aws_scanner_config.bucket_athena_query_results())
        self.assertEqual("a-cloudtrail-logs-bucket", aws_scanner_config.bucket_cloudtrail_logs())
        self.assertEqual(30, aws_scanner_config.cloudtrail_log_retention_days())
        self.assertFalse(aws_scanner_config.org_unit_include_root_accounts())
        self.assertEqual("The Parent OU", aws_scanner_config.org_unit_parent())
        self.assertEqual("the_cloudtrail_role", aws_scanner_config.role_cloudtrail())
        self.assertEqual("the_orgs_role", aws_scanner_config.role_organizations())
        self.assertEqual("the_s3_role", aws_scanner_config.role_s3())
        self.assertEqual("the_ssm_role", aws_scanner_config.role_ssm())
        self.assertEqual(120, aws_scanner_config.session_duration_seconds())
        self.assertEqual(5, aws_scanner_config.tasks_executor())
        self.assertEqual("john.doo", aws_scanner_config.username())

    def test_config_not_found(self) -> None:
        with patch("builtins.open", mock_open(read_data="")):
            with self.assertRaisesRegex(SystemExit, "missing config: section 'accounts', key 'auth'"):
                AwsScannerConfig().account_auth()

    def test_config_file_is_missing(self) -> None:
        with patch("configparser.ConfigParser.read", return_value=[]):
            with self.assertLogs("AwsScannerConfig", level="INFO") as info_log:
                AwsScannerConfig()
        self.assertIn("Config file 'aws_scanner_config.ini' not found", info_log.output[0])
