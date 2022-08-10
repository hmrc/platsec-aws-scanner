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
    PutLogGroupRetentionPolicyAction,
    TagLogGroupAction,
    DeleteQueryLogAction,
    CreateLogGroupAction,
    PutLogGroupSubscriptionFilterAction,
    DeleteLogGroupSubscriptionFilterAction,
    PutRoute53LogGroupResourcePolicyAction,
)
from src.data.aws_common_types import ServiceName


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

    def test_enforcement_actions_with_existing_LogGroup_no_subscription_filter(self) -> None:

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
        config.logs_group_name = Mock(return_value="logs_route53_log_group_name")

        expectedLogGroups = [
            LogGroup(name="logs_route53_log_group_name", kms_key_id="kms_key_id"),
        ]

        logs.describe_log_groups = Mock(side_effect=lambda name: expectedLogGroups)
        kms.get_key = Mock(side_effect=lambda key_id: "kms_key_id")

        expectedQueryLogActionList: List[ComplianceAction] = []

        expectedQueryLogActionList.append(
            DeleteLogGroupSubscriptionFilterAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, config=config, service_name=ServiceName.route53))
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

    def test_enforcement_actions_with_existing_LogGroup_with_subscription_filter(self) -> None:

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
        logs.is_central_log_group = Mock(return_value=False)
        kms = Mock()
        config = Mock()
        config.logs_group_name = Mock(return_value="logs_route53_log_group_name")

        expectedLogGroups = [
            LogGroup(name="logs_route53_log_group_name", kms_key_id="kms_key_id"),
        ]

        logs.describe_log_groups = Mock(side_effect=lambda name: expectedLogGroups)
        kms.get_key = Mock(side_effect=lambda key_id: "kms_key_id")

        expectedQueryLogActionList: List[ComplianceAction] = []

        expectedQueryLogActionList.append(
            PutLogGroupSubscriptionFilterAction(service_name=ServiceName.route53, config=config, logs=logs)
        )
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, config=config, service_name=ServiceName.route53))
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

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, True)

    def test_enforcement_actions_with_new_LogGroup_no_subscription_filter(self) -> None:

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
        config.logs_group_name = Mock(return_value="logs_route53_log_group_name")

        expectedLogGroups: List[Any] = []

        logs.describe_log_groups = Mock(side_effect=lambda name: expectedLogGroups)
        kms.get_key = Mock(side_effect=lambda key_id: "kms_key_id")

        expectedQueryLogActionList: List[ComplianceAction] = []
        expectedQueryLogActionList.append(
            PutRoute53LogGroupResourcePolicyAction(logs=logs, config=config, policy_document="a_policy_document")
        )
        expectedQueryLogActionList.append(
            CreateLogGroupAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, config=config, service_name=ServiceName.route53))
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

    def test_enforcement_actions_with_new_LogGroup_with_subscription_filter(self) -> None:

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
        logs.is_central_log_group = Mock(return_value=True)
        kms = Mock()
        config = Mock()
        config.logs_group_name = Mock(return_value="logs_route53_log_group_name")
        config.logs_log_group_destination = Mock(return_value="arn:aws:logs:::destination:central")

        expectedLogGroups: List[Any] = []

        logs.describe_log_groups = Mock(side_effect=lambda name: expectedLogGroups)
        kms.get_key = Mock(side_effect=lambda key_id: "kms_key_id")

        expectedQueryLogActionList: List[ComplianceAction] = []
        expectedQueryLogActionList.append(
            PutRoute53LogGroupResourcePolicyAction(logs=logs, config=config, policy_document="a_policy_document")
        )
        expectedQueryLogActionList.append(
            CreateLogGroupAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, config=config, service_name=ServiceName.route53)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, config=config, service_name=ServiceName.route53))
        expectedQueryLogActionList.append(
            PutLogGroupSubscriptionFilterAction(service_name=ServiceName.route53, config=config, logs=logs)
        )
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

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, True)
