# type: ignore
from unittest import TestCase
from unittest.mock import Mock

from src.aws_parallel_task_runner import AwsParallelTaskRunner
from src.data.aws_scanner_exceptions import AwsScannerException
from src.clients.aws_athena_client import AwsAthenaClient
from src.clients.aws_s3_client import AwsS3Client

from tests import _raise
from tests.test_types_generator import account, cloudtrail_task, partition, s3_task, task_report


def run_task_1(client: AwsAthenaClient):
    return {"outcome_1": "success_1"}


def run_task_2(client: AwsS3Client):
    return {"outcome_2": "success_2"}


def run_failing_task(client: AwsAthenaClient):
    _raise(AwsScannerException("oops"))


class TestAwsParallelTaskRunner(TestCase):
    def test_run_tasks(self) -> None:
        succeeding_task_1 = cloudtrail_task(description="some task")
        succeeding_task_1._run_task = run_task_1

        succeeding_task_2 = s3_task(description="other task")
        succeeding_task_2._run_task = run_task_2

        failing_task = cloudtrail_task(account=account("5678", "wrong account"), description="boom")
        failing_task._run_task = run_failing_task

        tasks = [succeeding_task_1, failing_task, succeeding_task_2]

        with self.assertLogs("AwsParallelTaskRunner", level="ERROR") as error_log:
            reports = AwsParallelTaskRunner(Mock()).run(tasks)

        self.assertEqual(2, len(reports), "there should only be two task reports")
        self.assertIn(
            task_report(description="some task", results={"outcome_1": "success_1"}, partition=partition()), reports
        )
        self.assertIn(
            task_report(description="other task", results={"outcome_2": "success_2"}, partition=None), reports
        )

        expected_error_msg = (
            "ERROR:AwsParallelTaskRunner:task 'boom' for 'wrong account (5678)' with AwsAthenaDataPartition(year='2020'"
            ", month='11', region='eu') failed with: 'AwsScannerException: oops'"
        )
        self.assertEqual([expected_error_msg], error_log.output)
