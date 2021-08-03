from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask

from tests.test_types_generator import account, task_report, vpc


class TestAwsAuditVPCFlowLogsTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        task = AwsAuditVPCFlowLogsTask(account(), enforce=False)
        ec2_client = Mock(list_vpcs=Mock(return_value=[vpc(), vpc()]))
        vpcs_audit = task.run(ec2_client)
        report = task_report(
            account(), "audit VPC flow logs compliance", partition=None, results={"vpcs": [vpc(), vpc()]}
        )
        self.assertEqual(report, vpcs_audit)
