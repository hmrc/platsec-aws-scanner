from unittest import TestCase
from unittest.mock import Mock, call, patch

from src.data.aws_scanner_exceptions import AwsScannerException
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask

from tests.test_types_generator import account, cloudtrail_task, partition, task_report


class TestAwsCloudTrailTask(TestCase):
    def test_randomise_name(self) -> None:
        task_1 = cloudtrail_task()
        task_2 = cloudtrail_task()
        self.assertTrue(task_1._database.startswith("some_prefix_account_id"))
        self.assertEqual(33, len(task_1._database))
        self.assertTrue(task_2._database.startswith("some_prefix_account_id"))
        self.assertEqual(33, len(task_2._database))
        self.assertTrue(task_1._database != task_2._database)

    def test_setup(self) -> None:
        mock_athena = Mock()
        t = cloudtrail_task()
        t._setup(mock_athena)
        mock_athena.assert_has_calls(
            [
                call.create_database(t._database),
                call.create_table(t._database, account()),
                call.add_partition(t._database, account(), partition()),
            ]
        )

    def test_teardown(self) -> None:
        mock_athena = Mock()
        t = cloudtrail_task()
        t._teardown(mock_athena)
        mock_athena.assert_has_calls(
            [
                call.drop_table(t._database, account().identifier),
                call.drop_database(t._database),
            ]
        )

    def test_run(self) -> None:
        task_class = "src.tasks.aws_cloudtrail_task.AwsCloudTrailTask"
        results = {"key": "val"}
        mock_athena = Mock()
        mocks = Mock(setup=Mock(), task=Mock(return_value=results), teardown=Mock())

        with patch(f"{task_class}._setup", mocks.setup):
            with patch(f"{task_class}._run_task", mocks.task):
                with patch(f"{task_class}._teardown", mocks.teardown):
                    self.assertEqual(task_report(), cloudtrail_task().run(mock_athena))
        mocks.assert_has_calls([call.setup(mock_athena), call.task(mock_athena), call.teardown(mock_athena)])

    def test_run_failure(self) -> None:
        task_class = "src.tasks.aws_cloudtrail_task.AwsCloudTrailTask"
        mock_athena = Mock()
        mocks = Mock(setup=Mock(), task=Mock(side_effect=AwsScannerException), teardown=Mock())

        with patch(f"{task_class}._setup", mocks.setup):
            with patch(f"{task_class}._run_task", mocks.task):
                with patch(f"{task_class}._teardown", mocks.teardown):
                    with self.assertRaises(AwsScannerException):
                        cloudtrail_task().run(mock_athena)
        mocks.assert_has_calls([call.setup(mock_athena), call.task(mock_athena), call.teardown(mock_athena)])

    def test_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            cloudtrail_task()._run_task(Mock())

    def test_run_query(self) -> None:
        query = "SELECT stuff FROM table WHERE thing = bla"
        results = ["some query results"]
        mock_athena = Mock(run_query=Mock(return_value=results))
        t = cloudtrail_task()
        self.assertEqual(results, t._run_query(mock_athena, query))
        mock_athena.run_query.assert_called_once_with(database=t._database, query=query)

    def test_read_value(self) -> None:
        results = [
            {"Data": [{"VarCharValue": "ssm.amazonaws.com"}, {"VarCharValue": "1024"}]},
            {"Data": [{"VarCharValue": "some.service"}, {"VarCharValue": "42"}]},
        ]
        self.assertEqual("ssm.amazonaws.com", AwsCloudTrailTask._read_value(results, 0, 0))
        self.assertEqual("1024", AwsCloudTrailTask._read_value(results, 0, 1))
        self.assertEqual("some.service", AwsCloudTrailTask._read_value(results, 1, 0))
        self.assertEqual("42", AwsCloudTrailTask._read_value(results, 1, 1))

    def test_str(self) -> None:
        self.assertEqual(
            (
                "task 'task' for 'account_name (account_id)' with "
                "AwsAthenaDataPartition(year='2020', month='09', region='eu')"
            ),
            str(cloudtrail_task(partition=partition(2020, 9))),
        )
