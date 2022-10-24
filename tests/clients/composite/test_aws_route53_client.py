from unittest.mock import Mock
from unittest import TestCase
from typing import List
from src.clients.aws_log_group_client import AwsLogGroupClient
from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.data.aws_logs_types import LogGroup
from src.aws_scanner_config import AwsScannerConfig as Config

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
    PutLogGroupResourcePolicyAction,
)
from tests.test_types_generator import expected_log_group


class TestAwsRoute53Client(TestCase):

    config = Config()

    def test_enforcement_actions_no_hostedZones(self) -> None:

        hostedZones: Dict[Any, Any] = {}

        account = Account(identifier="AAAAAAAAAA", name="AAAAAAAA")
        boto_route53 = Mock()
        iam = Mock()
        logs = Mock()
        log_group = AwsLogGroupClient(logs=logs)

        expectedQueryLogActionList: List[ComplianceAction] = []

        client = AwsRoute53Client(boto_route53, iam, log_group)

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, False)

    def test_route_53_does_nothing_when_all_correct(self) -> None:
        log_group_config = Config().logs_route53_query_log_group_config()

        account = Account(identifier="AAAAAAAAAA", name="AAAAAAAA")
        hostedZones: Dict[Any, Any] = {
            "/hostedzone/AAAABBBBCCCCDD": route53Type.Route53Zone(
                id="/hostedzone/AAAABBBBCCCCDD",
                name="public.aws.scanner.gov.uk.",
                privateZone=False,
                queryLog="arn:aws:logs:us-east-1:"
                + account.identifier
                + ":log-group:"
                + log_group_config.logs_group_name,
            )
        }

        boto_route53 = Mock()
        boto_route53.list_hosted_zones = Mock(return_value=hostedZones)
        boto_route53.list_query_logging_configs = Mock(
            return_value={"QueryLoggingConfigs": [{"CloudWatchLogsLogGroupArn": "foo"}]}
        )
        iam = Mock()
        logs = Mock()
        logs.is_central_log_group = Mock(return_value=True)
        test_policy = "some policy"
        logs.logs_resource_policy_document = Mock(return_value=test_policy)
        log_group_client = AwsLogGroupClient(logs=logs)
        logs.get_resource_policy = Mock(return_value=test_policy)

        logs.find_log_group = Mock(return_value=expected_log_group(log_group_config))

        client = AwsRoute53Client(boto_route53, iam, log_group_client)

        assert [] == client.enforcement_actions(account, hostedZones, True)

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
        boto_route53.list_query_logging_configs = Mock(return_value={"QueryLoggingConfigs": []})
        iam = Mock()
        logs = Mock()
        logs.get_resource_policy = Mock(return_value=None)
        log_group = AwsLogGroupClient(logs=logs)

        log_group_config = Config().logs_route53_query_log_group_config()

        expectedLogGroup = LogGroup(
            name="logs_route53_log_group_name", kms_key_id="kms_key_id", retention_days=0, arn=""
        )

        logs.find_log_group = Mock(side_effect=lambda name: expectedLogGroup)

        expectedQueryLogActionList: List[ComplianceAction] = []

        expectedQueryLogActionList.append(
            DeleteLogGroupSubscriptionFilterAction(logs=logs, log_group_config=log_group_config)
        )
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, log_group_config=log_group_config)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, log_group_config=log_group_config))
        expectedQueryLogActionList.append(
            PutLogGroupResourcePolicyAction(
                logs=logs, log_group_config=log_group_config, policy_document={"a_policy_document": 1}
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(route53_client=boto_route53, hosted_zone_id="/hostedzone/AAAABBBBCCCCDD")
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                log_group_config=log_group_config,
                zone_id="/hostedzone/AAAABBBBCCCCDD",
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(route53_client=boto_route53, hosted_zone_id="/hostedzone/IIIIIIILLLLLLL")
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                log_group_config=log_group_config,
                zone_id="/hostedzone/IIIIIIILLLLLLL",
            )
        )
        client = AwsRoute53Client(boto_route53, iam, log_group)
        actual = client.enforcement_actions(account, hostedZones, False)

        assert expectedQueryLogActionList == actual

    def test_enforcement_actions_with_new_subscription_filter(self) -> None:
        log_group_config = Config().logs_route53_query_log_group_config()
        account = Account(identifier="AAAAAAAAAA", name="AAAAAAAA")
        hostedZones: Dict[Any, Any] = {
            "/hostedzone/AAAABBBBCCCCDD": route53Type.Route53Zone(
                id="/hostedzone/AAAABBBBCCCCDD",
                name="public.aws.scanner.gov.uk.",
                privateZone=False,
                queryLog="arn:aws:logs:us-east-1:"
                + account.identifier
                + ":log-group:"
                + log_group_config.logs_group_name,
            )
        }

        boto_route53 = Mock()
        boto_route53.list_hosted_zones = Mock(return_value=hostedZones)
        boto_route53.list_query_logging_configs = Mock(
            return_value={"QueryLoggingConfigs": [{"CloudWatchLogsLogGroupArn": "foo"}]}
        )
        iam = Mock()
        logs = Mock()
        logs.is_central_log_group = Mock(return_value=False)
        test_policy = "some policy"
        logs.logs_resource_policy_document = Mock(return_value=test_policy)
        log_group_client = AwsLogGroupClient(logs=logs)
        logs.get_resource_policy = Mock(return_value=test_policy)

        log_group = expected_log_group(log_group_config)
        log_group.subscription_filters = []
        logs.find_log_group = Mock(return_value=log_group)

        expectedQueryLogActionList: List[ComplianceAction] = []

        expectedQueryLogActionList.append(
            PutLogGroupSubscriptionFilterAction(log_group_config=log_group_config, logs=logs)
        )
        client = AwsRoute53Client(boto_route53, iam, log_group_client)

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
        boto_route53.list_query_logging_configs = Mock(return_value={"QueryLoggingConfigs": []})
        iam = Mock()
        logs = Mock()
        log_group = AwsLogGroupClient(logs=logs)
        log_group_config = Config().logs_route53_query_log_group_config()

        expectedLogGroups: List[Any] = []

        logs.find_log_group = Mock(side_effect=lambda name: expectedLogGroups)
        logs.get_resource_policy = Mock(return_value=None)

        expectedQueryLogActionList: List[ComplianceAction] = []
        expectedQueryLogActionList.append(CreateLogGroupAction(logs=logs, log_group_config=log_group_config))
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, log_group_config=log_group_config)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, log_group_config=log_group_config))
        expectedQueryLogActionList.append(
            PutLogGroupResourcePolicyAction(
                logs=logs, log_group_config=log_group_config, policy_document={"a_policy_document": 1}
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(route53_client=boto_route53, hosted_zone_id="/hostedzone/AAAABBBBCCCCDD")
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                log_group_config=log_group_config,
                zone_id="/hostedzone/AAAABBBBCCCCDD",
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(route53_client=boto_route53, hosted_zone_id="/hostedzone/IIIIIIILLLLLLL")
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                log_group_config=log_group_config,
                zone_id="/hostedzone/IIIIIIILLLLLLL",
            )
        )
        client = AwsRoute53Client(boto_route53, iam, log_group)

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
        boto_route53.list_query_logging_configs = Mock(return_value={"QueryLoggingConfigs": []})
        iam = Mock()
        logs = Mock()
        logs.is_central_log_group = Mock(return_value=True)
        log_group = AwsLogGroupClient(logs=logs)

        log_group_config = Config().logs_route53_query_log_group_config()

        expectedLogGroups: List[Any] = []

        logs.find_log_group = Mock(side_effect=lambda name: expectedLogGroups)

        expectedQueryLogActionList: List[ComplianceAction] = []
        expectedQueryLogActionList.append(CreateLogGroupAction(logs=logs, log_group_config=log_group_config))
        expectedQueryLogActionList.append(
            PutLogGroupRetentionPolicyAction(logs=logs, log_group_config=log_group_config)
        )
        expectedQueryLogActionList.append(TagLogGroupAction(logs=logs, log_group_config=log_group_config))
        expectedQueryLogActionList.append(
            PutLogGroupSubscriptionFilterAction(log_group_config=log_group_config, logs=logs)
        )
        expectedQueryLogActionList.append(
            PutLogGroupResourcePolicyAction(
                logs=logs, log_group_config=log_group_config, policy_document={"a_policy_document": 1}
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(route53_client=boto_route53, hosted_zone_id="/hostedzone/AAAABBBBCCCCDD")
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                log_group_config=self.config.logs_route53_query_log_group_config(),
                zone_id="/hostedzone/AAAABBBBCCCCDD",
            )
        )
        expectedQueryLogActionList.append(
            DeleteQueryLogAction(route53_client=boto_route53, hosted_zone_id="/hostedzone/IIIIIIILLLLLLL")
        )
        expectedQueryLogActionList.append(
            CreateQueryLogAction(
                account=account,
                route53_client=boto_route53,
                iam=iam,
                log_group_config=self.config.logs_route53_query_log_group_config(),
                zone_id="/hostedzone/IIIIIIILLLLLLL",
            )
        )

        client = AwsRoute53Client(boto_route53, iam, log_group)

        assert expectedQueryLogActionList == client.enforcement_actions(account, hostedZones, True)
