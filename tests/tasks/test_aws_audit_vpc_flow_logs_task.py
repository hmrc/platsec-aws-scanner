from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from typing import AbstractSet

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_ec2_actions import EC2Action
from src.data.aws_ec2_types import Vpc

from tests.test_types_generator import (
    aws_audit_vpc_flow_logs_task,
    create_flow_log_action,
    delete_flow_log_action,
    task_report,
    vpc,
)

vpc_client = AwsVpcClient(ec2=AwsEC2Client(Mock()), iam=Mock(), logs=Mock())
vpcs = [vpc(id="vpc-1"), vpc(id="vpc-2")]
actions = [delete_flow_log_action(flow_log_id="fl-4"), create_flow_log_action(vpc_id="vpc-7")]
results = {"vpcs": vpcs, "enforcement_actions": actions}
report = task_report(description="audit VPC flow logs compliance", partition=None, results=results)


def enforcement_actions(v: Vpc) -> AbstractSet[EC2Action]:
    return {"vpc-1": {delete_flow_log_action("fl-4")}, "vpc-2": {create_flow_log_action("vpc-7")}}[v.id]


@patch("src.tasks.aws_audit_vpc_flow_logs_task.enforcement_actions", side_effect=enforcement_actions)
@patch.object(AwsEC2Client, "list_vpcs", return_value=vpcs)
@patch.object(AwsEC2Client, "apply", return_value=actions)
class TestAwsAuditVPCFlowLogsTask(AwsScannerTestCase):
    def test_run_audit_task(self, mock_apply, _, __) -> None:
        self.assertEqual(report, aws_audit_vpc_flow_logs_task(enforce=False).run(vpc_client))
        mock_apply.assert_not_called()

    def test_run_enforcement_task(self, mock_apply, _, __) -> None:
        self.assertEqual(report, aws_audit_vpc_flow_logs_task(enforce=True).run(vpc_client))
        mock_apply.assert_called_once_with(actions)
