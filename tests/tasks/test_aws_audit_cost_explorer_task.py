from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask

from tests.test_types_generator import account


class TestAwsAuditCostExplorerTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        cost_explorer_client = Mock(get_aws_cost_explorer=Mock(return_value={}))

        task_report = AwsAuditCostExplorerTask(account(), "a_service", "2021", "08")._run_task(cost_explorer_client)
        self.assertEqual({}, task_report)
