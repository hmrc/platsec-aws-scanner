from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import mock_open, patch

from src.data.aws_organizations_types import Account
from src.aws_scanner_config import AwsScannerConfig


class TestAwsScannerConfig(AwsScannerTestCase):
    def test_init_config(self) -> None:
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

    def test_config_not_found(self) -> None:
        with patch("builtins.open", mock_open(read_data="")):
            with self.assertRaisesRegex(SystemExit, "missing config: section 'accounts', key 'auth'"):
                AwsScannerConfig().account_auth()

    def test_config_file_is_missing(self) -> None:
        with patch("configparser.ConfigParser.read", return_value=[]):
            with self.assertRaisesRegex(SystemExit, "aws_scanner_config.ini"):
                AwsScannerConfig()
