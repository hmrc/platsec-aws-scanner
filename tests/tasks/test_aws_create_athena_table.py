from unittest import TestCase
from unittest.mock import Mock

from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.tasks.aws_create_athena_table_task import AwsCreateAthenaTableTask

from tests.test_types_generator import account, partition, TEST_REGION


class TestAwsCreateAthenaTableTask(TestCase):
    def test_aws_create_athena_table_task(self) -> None:
        task = AwsCreateAthenaTableTask(account=account(), partition=partition(), region=TEST_REGION)
        self.assertIsInstance(task, AwsCloudTrailTask)

        mock_athena = Mock()
        run_results = task._run_task(mock_athena)

        mock_athena.assert_not_called()
        self.assertEqual("account_id", run_results["table"])
        self.assertTrue(run_results["database"].startswith("some_prefix_account_id_"))

    def test_teardown_do_nothing(self) -> None:
        task = AwsCreateAthenaTableTask(account=account(), partition=partition(), region=TEST_REGION)
        mock_athena = Mock()
        task._teardown(mock_athena)
        mock_athena.assert_not_called()
