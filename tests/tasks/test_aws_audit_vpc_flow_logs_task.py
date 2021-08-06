from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask

from tests.test_types_generator import account


class TestAwsAuditVPCFlowLogsTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        with self.assertRaises(NotImplementedError):
            AwsAuditVPCFlowLogsTask(account(), True)._run_task(Mock())
