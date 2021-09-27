from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from tests.test_types_generator import cost_explorer_task


class TestAwsCostExplorerTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            cost_explorer_task()._run_task(Mock())
