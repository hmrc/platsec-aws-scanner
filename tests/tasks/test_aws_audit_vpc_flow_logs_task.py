from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from typing import Sequence

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_ec2_types import Vpc

from tests.test_types_generator import (
    aws_audit_vpc_flow_logs_task,
    create_flow_log_action,
    delete_flow_log_action,
    task_report,
    vpc,
)

vpc_client = AwsVpcClient(ec2=Mock(), iam=Mock(), logs=Mock(), kms=Mock())
vpcs = [vpc(id="vpc-1"), vpc(id="vpc-2")]
actions = [delete_flow_log_action(flow_log_id="fl-4"), create_flow_log_action(vpc_id="vpc-7")]
results = {"vpcs": vpcs, "enforcement_actions": actions}
report = task_report(description="audit VPC flow logs compliance", partition=None, results=results)


def enforcement_actions(v: Sequence[Vpc]) -> Sequence[ComplianceAction]:
    return [delete_flow_log_action("fl-4"), create_flow_log_action("vpc-7")] if v == vpcs else []


@patch.object(AwsVpcClient, "enforcement_actions", side_effect=enforcement_actions)
@patch.object(AwsVpcClient, "list_vpcs", return_value=vpcs)
@patch.object(AwsVpcClient, "apply", return_value=actions)
class TestAwsAuditVPCFlowLogsTask(AwsScannerTestCase):
    def test_run_audit_task(self, mock_apply: Mock, _: Mock, __: Mock) -> None:
        self.assertEqual(report, aws_audit_vpc_flow_logs_task(enforce=False).run(vpc_client))
        mock_apply.assert_not_called()

    def test_run_enforcement_task(self, mock_apply: Mock, _: Mock, __: Mock) -> None:
        self.assertEqual(report, aws_audit_vpc_flow_logs_task(enforce=True).run(vpc_client))
        mock_apply.assert_called_once_with(actions)
