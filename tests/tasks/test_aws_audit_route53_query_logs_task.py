from src.data.aws_task_report import AwsTaskReport
from unittest import TestCase
from unittest.mock import Mock, patch

from typing import Sequence

from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.clients.aws_hostedZones_client import AwsHostedZonesClient
from src.data.aws_compliance_actions import ComplianceAction, ComplianceActionReport
from src.data.aws_route53_types import Route53Zone

from tests.test_types_generator import (
    aws_audit_route53_query_logs_task,
    compliance_action_report,
    create_query_log_action,
    delete_query_log_action,
    task_report,
    route53Zone,
)

route53_client = AwsRoute53Client(boto_route53=Mock(), iam=Mock(), logs=Mock(), kms=Mock(), config=Mock())
hostedZones = [route53Zone(id="1234", privateZone=False), route53Zone(id="5678", privateZone=True)]
# hostedZones = [route53Zone(id="1234"), route53Zone(id="5678")]
actions = [create_query_log_action(zone_id="1234"), delete_query_log_action(hosted_zone_id="5678")]


def enforcement_actions(z: Sequence[Route53Zone], with_sub_filter: bool) -> Sequence[ComplianceAction]:
    return (
        [delete_query_log_action(zone_id="5678"), create_query_log_action(zone_id="1234")]
        if z == hostedZones and with_sub_filter
        else []
    )


@patch.object(AwsRoute53Client, "enforcement_actions", side_effect=enforcement_actions)
@patch.object(AwsHostedZonesClient, "list_hosted_zones", return_value=hostedZones)
class TestAwsAuditRoute53QueryLogsTask(TestCase):
    def test_run_plan_task(self, _: Mock, __: Mock) -> None:
        action_reports = [
            compliance_action_report(
                description="Delete Route53 Query log",
                details=dict(zone_id="5678")
            ),
            compliance_action_report(
                description="Create Route53 query log",
                details=dict(zone_id="1234", log_group_name="/aws/route53/query_log"),
            ),
        ]
        report = self.expected_report(action_reports)
        self.assertEqual(
            report, aws_audit_route53_query_logs_task(enforce=False, with_subscription_filter=True).run(route53_client)
        )


    @staticmethod
    def expected_report(action_reports: Sequence[ComplianceActionReport]) -> AwsTaskReport:
        results = {"hostedZones": hostedZones, "enforcement_actions": action_reports}
        report = task_report(description="audit Route53 query logs compliance", partition=None, results=results)
        return report


    def test_run_apply_task(self, _: Mock, __: Mock) -> None:
        reports = [
            compliance_action_report(
                status="applied", description="Delete Route53 query log", details=dict(zone_id="5678")
            ),
            compliance_action_report(
                status="applied",
                description="Create Route53 query log",
                details=dict(zone_id="1234", log_group_name="/aws/route53/query_log"),
            ),
        ]
        self.assertEqual(
            self.expected_report(reports),
            aws_audit_route53_query_logs_task(enforce=True, with_subscription_filter=True).run(route53_client)
        )

