from unittest import TestCase
from unittest.mock import Mock, patch

from typing import Sequence

from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.clients.aws_hostedZones_client import AwsHostedZonesClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_route53_types import Route53Zone

from tests.test_types_generator import (
    aws_audit_route53_query_logs_task,
    create_query_log_action,
    delete_query_log_action,
    route53Zone,
    account,
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
    def test_run_papply_task(self, _: Mock, __: Mock) -> None:

        hostedZones = [route53Zone(id="1234", privateZone=False), route53Zone(id="5678", privateZone=True)]

        compliance_action_report1 = Mock()
        compliance_action_report1.apply = Mock()
        compliance_action_report2 = Mock()
        compliance_action_report2.apply = Mock()

        action_reports = [compliance_action_report1, compliance_action_report2]

        _route53 = Mock()
        _route53.list_hosted_zones = Mock(return_value=hostedZones)
        route53_client = Mock()
        route53_client._route53 = _route53

        route53_client.enforcement_actions = Mock(return_value=action_reports)

        aws_audit_route53_query_logs_task(enforce=True, with_subscription_filter=True).run(route53_client)

        _route53.list_hosted_zones.assert_called_once()
        route53_client.enforcement_actions.assert_called_once_with(account(), hostedZones, True)
        compliance_action_report1.apply.assert_called_once()
        compliance_action_report2.apply.assert_called_once()

    def test_run_plan_task(self, _: Mock, __: Mock) -> None:

        hostedZones = [route53Zone(id="1234", privateZone=False), route53Zone(id="5678", privateZone=True)]

        compliance_action_report1 = Mock()
        compliance_action_report1.apply = Mock()
        compliance_action_report2 = Mock()
        compliance_action_report2.apply = Mock()

        action_reports = [compliance_action_report1, compliance_action_report2]

        _route53 = Mock()
        _route53.list_hosted_zones = Mock(return_value=hostedZones)
        route53_client = Mock()
        route53_client._route53 = _route53

        route53_client.enforcement_actions = Mock(return_value=action_reports)

        aws_audit_route53_query_logs_task(enforce=False, with_subscription_filter=True).run(route53_client)

        _route53.list_hosted_zones.assert_called_once()
        route53_client.enforcement_actions.assert_called_once_with(account(), hostedZones, True)
        compliance_action_report1.plan.assert_called_once()
        compliance_action_report2.plan.assert_called_once()
