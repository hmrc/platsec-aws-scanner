from src.data.aws_task_report import AwsTaskReport
from unittest import TestCase
from unittest.mock import Mock, patch

from typing import Sequence

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_compliance_actions import ComplianceAction, ComplianceActionReport
from src.data.aws_ec2_types import Vpc

from tests.test_types_generator import (
    aws_audit_vpc_flow_logs_task,
    compliance_action_report,
    create_flow_log_action,
    delete_flow_log_action,
    task_report,
    vpc,
)

vpc_client = AwsVpcClient(ec2=Mock())
vpcs = [vpc(id="vpc-1"), vpc(id="vpc-2")]
actions = [delete_flow_log_action(flow_log_id="fl-4"), create_flow_log_action(vpc_id="vpc-7")]


def enforcement_actions(v: Sequence[Vpc]) -> Sequence[ComplianceAction]:
    return [delete_flow_log_action(flow_log_id="fl-4"), create_flow_log_action(vpc_id="vpc-7")] if v == vpcs else []


@patch.object(AwsVpcClient, "enforcement_actions", side_effect=enforcement_actions)
@patch.object(AwsVpcClient, "list_vpcs", return_value=vpcs)
class TestAwsAuditVPCFlowLogsTask(TestCase):
    def test_run_plan_task(self, _: Mock, __: Mock) -> None:
        action_reports = [
            compliance_action_report(description="Delete VPC flow log", details=dict(flow_log_id="fl-4")),
            compliance_action_report(
                description="Create VPC flow log",
                details=dict(vpc_id="vpc-7", log_bucket_arn="central_log_bucket"),
            ),
        ]
        report = self.expected_report(action_reports)
        self.assertEqual(report, aws_audit_vpc_flow_logs_task(enforce=False).run(vpc_client))

    @staticmethod
    def expected_report(action_reports: Sequence[ComplianceActionReport]) -> AwsTaskReport:
        results = {"vpcs": vpcs, "enforcement_actions": action_reports}
        report = task_report(description="audit VPC flow logs compliance", partition=None, results=results)
        return report

    def test_run_apply_task(self, _: Mock, __: Mock) -> None:
        reports = [
            compliance_action_report(
                status="applied", description="Delete VPC flow log", details=dict(flow_log_id="fl-4")
            ),
            compliance_action_report(
                status="applied",
                description="Create VPC flow log",
                details=dict(vpc_id="vpc-7", log_bucket_arn="central_log_bucket"),
            ),
        ]
        self.assertEqual(
            self.expected_report(reports),
            aws_audit_vpc_flow_logs_task(enforce=True).run(vpc_client),
        )
