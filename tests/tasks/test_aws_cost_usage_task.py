from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from tests.test_types_generator import cost_usage_task


class TestAwsCostUsageTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            cost_usage_task()._run_task(Mock())
