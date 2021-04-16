from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from tests.test_types_generator import account, aws_task, task_report


class TestAwsTaskTask(AwsScannerTestCase):
    def test_run(self) -> None:
        with patch("src.tasks.aws_task.AwsTask._run_task", return_value={"key": "val"}):
            self.assertEqual(task_report(partition=None), aws_task().run(Mock()))

    def test_get_account(self) -> None:
        task = aws_task()
        self.assertEqual(task.account, account())

    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            aws_task()._run_task(Mock())

    def test_str(self) -> None:
        self.assertEqual("task 'task' for 'account_name (account_id)'", str(aws_task()))
