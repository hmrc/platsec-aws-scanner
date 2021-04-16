from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from tests.test_types_generator import organizations_task


class TestAwsOrganizationsTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            organizations_task()._run_task(Mock())
