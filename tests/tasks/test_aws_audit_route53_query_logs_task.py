from unittest import TestCase
from unittest.mock import Mock

from tests.test_types_generator import (
    aws_audit_route53_query_logs_task,
    route53Zone,
    account,
)


class TestAwsAuditRoute53QueryLogsTask(TestCase):
    def test_run_papply_task(self) -> None:

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
        route53_client.enforcement_actions.assert_called_once_with(account(), hostedZones, True, False)
        compliance_action_report1.apply.assert_called_once()
        compliance_action_report2.apply.assert_called_once()

    def test_run_plan_task(self) -> None:

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
        route53_client.enforcement_actions.assert_called_once_with(account(), hostedZones, True, False)
        compliance_action_report1.plan.assert_called_once()
        compliance_action_report2.plan.assert_called_once()
