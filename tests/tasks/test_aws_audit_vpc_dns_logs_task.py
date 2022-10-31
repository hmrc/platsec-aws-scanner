from src.clients.aws_resolver_client import AwsResolverClient
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_task_report import AwsTaskReport
from unittest.mock import Mock

from typing import Sequence

from src.data.aws_compliance_actions import (
    ComplianceAction,
    ComplianceActionReport,
    PutLogGroupSubscriptionFilterAction,
)
from src.data.aws_ec2_types import Vpc
from src.aws_scanner_config import AwsScannerConfig
from src.clients.aws_logs_client import AwsLogsClient

from tests.test_types_generator import (
    create_flow_log_action,
    delete_flow_log_action,
    task_report,
    vpc,
    aws_audit_vpc_dns_logs_task,
)


vpcs = [vpc(id="vpc-1"), vpc(id="vpc-2")]


def enforcement_actions(v: Sequence[Vpc], with_sub_filter: bool) -> Sequence[ComplianceAction]:
    return [
        delete_flow_log_action(flow_log_id="fl-4"),
        create_flow_log_action(vpc_id="vpc-7"),
        PutLogGroupSubscriptionFilterAction(
            Mock(spec=AwsLogsClient), AwsScannerConfig().logs_vpc_dns_log_group_config()
        ),
    ]


def test_run_plan_task() -> None:
    actions = enforcement_actions(vpcs, False)
    resolver = Mock(spec=AwsResolverClient)
    resolver.list_config_associations = Mock(return_value={})
    vpc_client = Mock(spec=AwsVpcClient)
    vpc_client.resolver = resolver
    vpc_client.enforcement_dns_log_actions = Mock(return_value=actions)
    vpc_client.list_vpcs = Mock(return_value=vpcs)
    expected_action_reports = [
        ComplianceActionReport(description="Delete VPC flow log", status=None, details={"flow_log_id": "fl-4"}),
        ComplianceActionReport(
            description="Create VPC flow log",
            status=None,
            details={"vpc_id": "vpc-7", "log_group_name": "/vpc/flow_log"},
        ),
        ComplianceActionReport(
            description="Put central /vpc/central_dns_log_name log group subscription filter",
            status=None,
            details={
                "log_group_name": "/vpc/central_dns_log_name",
                "destination_arn": "arn:aws:logs:::destination:some-dns-central",
            },
        ),
    ]

    assert expected_report(expected_action_reports) == aws_audit_vpc_dns_logs_task(
        enforce=False, with_subscription_filter=True, skip_tags=False
    ).run(vpc_client)


def expected_report(action_reports: Sequence[ComplianceActionReport]) -> AwsTaskReport:
    results = {"associations": {}, "enforcement_actions": action_reports}
    report = task_report(description="audit VPC dns logs compliance", partition=None, results=results)
    return report


def test_run_apply_task() -> None:
    actions = enforcement_actions(vpcs, False)
    resolver = Mock(spec=AwsResolverClient)
    resolver.list_config_associations = Mock(return_value={})
    vpc_client = Mock(spec=AwsVpcClient)
    vpc_client.resolver = resolver
    vpc_client.enforcement_dns_log_actions = Mock(return_value=actions)
    vpc_client.list_vpcs = Mock(return_value=vpcs)
    expected_action_reports = [
        ComplianceActionReport(description="Delete VPC flow log", status="applied", details={"flow_log_id": "fl-4"}),
        ComplianceActionReport(
            description="Create VPC flow log",
            status="applied",
            details={"vpc_id": "vpc-7", "log_group_name": "/vpc/flow_log"},
        ),
        ComplianceActionReport(
            description="Put central /vpc/central_dns_log_name log group subscription filter",
            status="applied",
            details={
                "log_group_name": "/vpc/central_dns_log_name",
                "destination_arn": "arn:aws:logs:::destination:some-dns-central",
            },
        ),
    ]

    assert expected_report(expected_action_reports) == aws_audit_vpc_dns_logs_task(
        enforce=True, with_subscription_filter=True, skip_tags=False
    ).run(vpc_client)
