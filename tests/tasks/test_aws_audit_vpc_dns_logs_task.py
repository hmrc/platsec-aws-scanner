from src.data.aws_task_report import AwsTaskReport
from unittest.mock import Mock

from typing import Sequence

from src.data.aws_compliance_actions import ComplianceAction, ComplianceActionReport
from src.data.aws_ec2_types import Vpc

from tests.test_types_generator import (
    create_flow_log_action,
    delete_flow_log_action,
    task_report,
    vpc,
    aws_audit_vpc_dns_logs_task,
)


vpcs = [vpc(id="vpc-1"), vpc(id="vpc-2")]


def enforcement_actions(v: Sequence[Vpc], with_sub_filter: bool) -> Sequence[ComplianceAction]:
    return (
        [delete_flow_log_action(flow_log_id="fl-4"), create_flow_log_action(vpc_id="vpc-7")]
        if v == vpcs and with_sub_filter
        else []
    )


def test_run_plan_task() -> None:
    actions = enforcement_actions(vpcs, False)
    vpc_client = Mock()
    vpc_client.enforcement_dns_log_actions = Mock(return_value=actions)
    vpc_client.list_vpcs = Mock(return_value=vpcs)

    assert expected_report([]) == aws_audit_vpc_dns_logs_task(enforce=False, with_subscription_filter=True).run(
        vpc_client
    )


def expected_report(action_reports: Sequence[ComplianceActionReport]) -> AwsTaskReport:
    results = {"vpcs": vpcs, "enforcement_actions": action_reports}
    report = task_report(description="audit VPC dns logs compliance", partition=None, results=results)
    return report


def test_run_apply_task() -> None:

    vpc_client = Mock()
    vpc_client.enforcement_dns_log_actions = Mock(return_value=[])
    vpc_client.list_vpcs = Mock(return_value=vpcs)

    assert expected_report([]) == aws_audit_vpc_dns_logs_task(enforce=True, with_subscription_filter=True).run(
        vpc_client
    )
