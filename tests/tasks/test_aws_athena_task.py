from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from tests.test_types_generator import athena_task


class TestAwsAthenaTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            athena_task()._run_task(Mock())
