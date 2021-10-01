# type: ignore
from unittest import TestCase
from unittest.mock import Mock

from src.aws_parallel_task_runner import AwsParallelTaskRunner
from src.data.aws_scanner_exceptions import AwsScannerException

from tests import _raise
from tests.test_types_generator import account, athena_task, task_report


class TestAwsParallelTaskRunner(TestCase):
    def test_run_tasks(self) -> None:
        succeeding_task_1 = athena_task(description="some task")
        succeeding_task_1._run_task = lambda _: {"outcome_1": "success_1"}

        succeeding_task_2 = athena_task(description="other task")
        succeeding_task_2._run_task = lambda _: {"outcome_2": "success_2"}

        failing_task = athena_task(account=account("5678", "wrong account"), description="boom")
        failing_task._run_task = lambda _: _raise(AwsScannerException("oops"))

        tasks = [succeeding_task_1, failing_task, succeeding_task_2]

        with self.assertLogs("AwsParallelTaskRunner", level="ERROR") as error_log:
            reports = AwsParallelTaskRunner(Mock()).run(tasks)

        self.assertEqual(2, len(reports), "there should only be two task reports")
        self.assertIn(task_report(description="some task", results={"outcome_1": "success_1"}, partition=None), reports)
        self.assertIn(
            task_report(description="other task", results={"outcome_2": "success_2"}, partition=None), reports
        )

        self.assertEqual(
            ["ERROR:AwsParallelTaskRunner:task 'boom' for 'wrong account (5678)' failed with: 'oops'"],
            error_log.output,
        )
