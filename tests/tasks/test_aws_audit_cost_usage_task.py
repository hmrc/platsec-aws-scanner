from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_cost_usage_task import AwsAuditCostExplorerTask

from tests.test_types_generator import account


class TestAwsAuditCostExplorerTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        cost_usage_client = Mock(get_aws_cost_usage=Mock(return_value={}))

        task_report = AwsAuditCostExplorerTask(account(), "a_service", "2021", "08")._run_task(cost_usage_client)
        self.assertEqual({}, task_report)
