from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from datetime import date

from src.aws_task_builder import AwsTaskBuilder
from src.tasks.aws_athena_cleaner_task import AwsAthenaCleanerTask
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask
from src.tasks.aws_list_accounts_task import AwsListAccountsTask
from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask
from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask
from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask
from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask
from src.tasks.aws_task import AwsTask

from tests.test_types_generator import account, partition


class TestAwsTaskBuilder(AwsScannerTestCase):
    def test_principal_by_ip_finder_tasks(self) -> None:
        mock_orgs = Mock(get_target_accounts=Mock(return_value=[(account("1", "one")), (account("2", "two"))]))
        year, month, source_ip = date.today().year, date.today().month, "127.0.0.1"
        tasks = AwsTaskBuilder(mock_orgs).principal_by_ip_finder_tasks(year, month, source_ip)

        self.assert_ip_tasks_equal(AwsPrincipalByIPFinderTask(account("1", "one"), partition(), "127.0.0.1"), tasks[0])
        self.assert_ip_tasks_equal(AwsPrincipalByIPFinderTask(account("2", "two"), partition(), "127.0.0.1"), tasks[1])

    def test_service_usage_scanner_tasks(self) -> None:
        mock_orgs = Mock(get_target_accounts=Mock(return_value=[(account("1", "one")), (account("2", "two"))]))
        year, month, service = date.today().year, date.today().month, "s3"
        tasks = AwsTaskBuilder(mock_orgs).service_usage_scanner_tasks(year, month, service)

        self.assert_service_tasks_equal(AwsServiceUsageScannerTask(account("1", "one"), partition(), "s3"), tasks[0])
        self.assert_service_tasks_equal(AwsServiceUsageScannerTask(account("2", "two"), partition(), "s3"), tasks[1])

    def test_role_usage_scanner_tasks(self) -> None:
        mock_orgs = Mock(get_target_accounts=Mock(return_value=[(account("1", "one")), (account("2", "two"))]))
        year, month, role = date.today().year, date.today().month, "SomeRole"
        tasks = AwsTaskBuilder(mock_orgs).role_usage_scanner_tasks(year, month, role)

        self.assert_role_tasks_equal(AwsRoleUsageScannerTask(account("1", "one"), partition(), "SomeRole"), tasks[0])
        self.assert_role_tasks_equal(AwsRoleUsageScannerTask(account("2", "two"), partition(), "SomeRole"), tasks[1])

    def test_create_athena_table_tasks(self) -> None:
        mock_orgs = Mock(find_account_by_ids=Mock(return_value=[(account("8", "eight")), (account("3", "three"))]))
        year, month = date.today().year, date.today().month
        tasks = AwsTaskBuilder(mock_orgs, ["8", "3"]).create_athena_table_tasks(year, month)

        self.assert_cloudtrail_tasks_equal(AwsCreateAthenaTableTask(account("8", "eight"), partition()), tasks[0])
        self.assert_cloudtrail_tasks_equal(AwsCreateAthenaTableTask(account("3", "three"), partition()), tasks[1])

    def test_clean_athena_tasks(self) -> None:
        self.assertEqual([AwsAthenaCleanerTask()], AwsTaskBuilder(Mock()).clean_athena_tasks())

    def test_list_accounts_tasks(self) -> None:
        self.assertEqual([AwsListAccountsTask()], AwsTaskBuilder(Mock()).list_accounts_tasks())

    def test_list_ssm_parameters_tasks(self) -> None:
        mock_orgs = Mock(find_account_by_ids=Mock(return_value=[(account("2", "two")), (account("4", "four"))]))
        tasks = AwsTaskBuilder(mock_orgs, ["4", "2"]).list_ssm_parameters_tasks()

        self.assert_tasks_equal(AwsListSSMParametersTask(account("2", "two")), tasks[0])
        self.assert_tasks_equal(AwsListSSMParametersTask(account("4", "four")), tasks[1])

    def assert_tasks_equal(self, expected: AwsTask, actual: AwsTask) -> None:
        self.assertEqual(expected._account, actual._account)

    def assert_cloudtrail_tasks_equal(self, expected: AwsCloudTrailTask, actual: AwsCloudTrailTask) -> None:
        self.assert_tasks_equal(expected, actual)
        self.assertEqual(expected._partition, actual._partition)

    def assert_ip_tasks_equal(self, expected: AwsPrincipalByIPFinderTask, actual: AwsPrincipalByIPFinderTask) -> None:
        self.assert_cloudtrail_tasks_equal(expected, actual)
        self.assertEqual(expected._source_ip, actual._source_ip)

    def assert_service_tasks_equal(
        self, expected: AwsServiceUsageScannerTask, actual: AwsServiceUsageScannerTask
    ) -> None:
        self.assert_cloudtrail_tasks_equal(expected, actual)
        self.assertEqual(expected._service, actual._service)

    def assert_role_tasks_equal(self, expected: AwsRoleUsageScannerTask, actual: AwsRoleUsageScannerTask) -> None:
        self.assert_cloudtrail_tasks_equal(expected, actual)
        self.assertEqual(expected._role, actual._role)
