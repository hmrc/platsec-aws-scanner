from unittest.mock import Mock
from unittest import TestCase
from typing import List
from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.data.aws_logs_types import LogGroup

from typing import Dict, Any
import src.data.aws_route53_types as route53Type
from src.data.aws_organizations_types import Account
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_compliance_actions import (
    CreateQueryLogAction,
    PutRoute53LogGroupRetentionPolicyAction,
    TagRoute53LogGroupAction,
    DeleteQueryLogAction,
    CreateRoute53LogGroupAction,
)


class TestAwsRoute53Client(TestCase):
    def test_enforcement_actions_no_hostedZones(self) -> None:

        hostedZones: Dict[Any, Any] = {}

        account = Account(identifier="AAAAAAAAAA", name="AAAAAAAA")
        boto_route53 = Mock()
        iam = Mock()
        logs = Mock()
        kms = Mock()
        config = Mock()

        expectedQueryLogActionList: List[ComplianceAction] = []

        client = AwsRoute53Client(boto_route53, iam, logs, kms, config)

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, False)

    def test_enforcement_actions_with_existing_LogGroup(self) -> None:

        hostedZones: Dict[Any, Any] = {
            "/hostedzone/AAAABBBBCCCCDD": route53Type.Route53Zone(
                id="/hostedzone/AAAABBBBCCCCDD",
                name="public.aws.scanner.gov.uk.",
                privateZone=False,
                queryLog="arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/public.aws.scanner.gov.uk.",
            ),
            "/hostedzone/IIIIIIILLLLLLL": route53Type.Route53Zone(
                id="/hostedzone/IIIIIIILLLLLLL",
                name="public.aws.scanner.gov.uk.",
                privateZone=False,
                queryLog="",
            ),
        }

        account = Account(identifier="AAAAAAAAAA", name="AAAAAAAA")
        boto_route53 = Mock()
        iam = Mock()
        logs = Mock()
        kms = Mock()
        config = Mock()
        config.logs_route53_log_group_name = Mock(return_value="logs_route53_log_group_name")

        expectedLogGroups = [
            LogGroup(name="logs_route53_log_group_name", kms_key_id="kms_key_id"),
        ]

        logs.describe_log_groups = Mock(side_effect=lambda name: expectedLogGroups)
        kms.get_key = Mock(side_effect=lambda key_id: "kms_key_id")

        expectedQueryLogActionList: List[ComplianceAction] = []
        expectedQueryLogActionList.append(PutRoute53LogGroupRetentionPolicyAction(logs=logs, config=config))
        expectedQueryLogActionList.append(TagRoute53LogGroupAction(logs=logs, config=config))
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(
                route53_client=boto_route53, config=config, hosted_zone_id="/hostedzone/AAAABBBBCCCCDD"
            )
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                config=config,
                zone_id="/hostedzone/AAAABBBBCCCCDD",
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(
                route53_client=boto_route53, config=config, hosted_zone_id="/hostedzone/IIIIIIILLLLLLL"
            )
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                config=config,
                zone_id="/hostedzone/IIIIIIILLLLLLL",
            )
        )
        client = AwsRoute53Client(boto_route53, iam, logs, kms, config)

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, False)

    def test_enforcement_actions_with_new_LogGroup(self) -> None:

        hostedZones: Dict[Any, Any] = {
            "/hostedzone/AAAABBBBCCCCDD": route53Type.Route53Zone(
                id="/hostedzone/AAAABBBBCCCCDD",
                name="public.aws.scanner.gov.uk.",
                privateZone=False,
                queryLog="arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/public.aws.scanner.gov.uk.",
            ),
            "/hostedzone/IIIIIIILLLLLLL": route53Type.Route53Zone(
                id="/hostedzone/IIIIIIILLLLLLL",
                name="public.aws.scanner.gov.uk.",
                privateZone=False,
                queryLog="",
            ),
        }

        account = Account(identifier="AAAAAAAAAA", name="AAAAAAAA")
        boto_route53 = Mock()
        iam = Mock()
        logs = Mock()
        kms = Mock()
        config = Mock()
        config.logs_route53_log_group_name = Mock(return_value="logs_route53_log_group_name")

        expectedLogGroups: List[Any] = []

        logs.describe_log_groups = Mock(side_effect=lambda name: expectedLogGroups)
        kms.get_key = Mock(side_effect=lambda key_id: "kms_key_id")

        expectedQueryLogActionList: List[ComplianceAction] = []
        expectedQueryLogActionList.append(CreateRoute53LogGroupAction(logs=logs, config=config))
        expectedQueryLogActionList.append(PutRoute53LogGroupRetentionPolicyAction(logs=logs, config=config))
        expectedQueryLogActionList.append(TagRoute53LogGroupAction(logs=logs, config=config))
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(
                route53_client=boto_route53, config=config, hosted_zone_id="/hostedzone/AAAABBBBCCCCDD"
            )
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                config=config,
                zone_id="/hostedzone/AAAABBBBCCCCDD",
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(
                route53_client=boto_route53, config=config, hosted_zone_id="/hostedzone/IIIIIIILLLLLLL"
            )
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                config=config,
                zone_id="/hostedzone/IIIIIIILLLLLLL",
            )
        )
        client = AwsRoute53Client(boto_route53, iam, logs, kms, config)

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, False)
