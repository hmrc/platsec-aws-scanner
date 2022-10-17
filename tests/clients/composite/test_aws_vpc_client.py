from __future__ import annotations

from typing import Sequence, Optional, Type, Dict, Any, List
from src.clients.aws_log_group_client import AwsLogGroupClient
from src.clients.aws_resolver_client import AwsResolverClient, ResolverQueryLogConfig

from src.data.aws_iam_types import Role, Policy
from src.data.aws_logs_types import LogGroup
from src.data.aws_scanner_exceptions import IamException
from unittest import TestCase
from unittest.mock import Mock
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_compliance_actions import (
    AssociateResolverQueryLogConfig,
    ComplianceAction,
    CreateLogGroupAction,
    DeleteResolverQueryLogConfig,
    DisassociateResolverQueryLogConfig,
    PutLogGroupRetentionPolicyAction,
    TagLogGroupAction,
    PutLogGroupSubscriptionFilterAction,
    CreateResolverQueryLogConfig,
)

from tests.test_types_generator import (
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    create_log_group_action,
    delete_flow_log_action,
    delete_flow_log_delivery_role_action,
    delete_vpc_log_group_subscription_filter_action,
    flow_log,
    key,
    log_group,
    policy,
    put_vpc_log_group_subscription_filter_action,
    put_log_group_retention_policy_action,
    role,
    subscription_filter,
    tag_flow_log_delivery_role_action,
    tag_log_group_action,
    vpc,
    tag,
    expected_subscription_filter,
    resolver_query_log_config,
    account,
    put_log_group_resource_policy_action,
    resource_policy_document,
)


class TestAwsVpcClient(TestCase):
    def test_list_vpcs(self) -> None:
        a_key = key()
        log_role = role(arn=str(flow_log().deliver_log_role_arn))
        group = log_group(kms_key_id=a_key.id, kms_key=a_key)
        expected_enriched_vpcs = [
            vpc(
                id="default-log-group-1",
                flow_logs=[flow_log(deliver_log_role_arn=None, deliver_log_role=None, log_group=group)],
            ),
            vpc(id="default-log-group-2", flow_logs=[flow_log(deliver_log_role=log_role, log_group_name=None)]),
        ]

        client = AwsVpcClientBuilder()
        client.with_default_vpc()
        client.logs.find_log_group.side_effect = [group]
        client.with_roles([role(), role(arn=str(flow_log().deliver_log_role_arn))])

        enriched = client.build().list_vpcs()

        self.assertEqual(len(enriched), 2)
        self.assertEqual(expected_enriched_vpcs, enriched)


class TestAwsLogDeliveryRoleCompliance(TestCase):
    def test_find_flow_log_delivery_role(self) -> None:
        delivery_role = role(name="vpc_flow_log_role")
        client = AwsVpcClientBuilder().with_roles([delivery_role])

        self.assertEqual(delivery_role, client.build()._find_flow_log_delivery_role())

    def test_flow_log_role_compliant(self) -> None:
        delivery_role = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:*"], "Resource": "*"}]})],
        )
        clientBuilder = AwsVpcClientBuilder()

        client = clientBuilder.build()
        self.assertTrue(client._is_flow_log_role_compliant(delivery_role))

    def test_flow_log_role_not_compliant(self) -> None:
        invalid_assume_policy = role(
            assume_policy={"Statement": [{"Action": "sts:other"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]})],
        )
        invalid_policy_document = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:bla"], "Resource": "*"}]})],
        )
        missing_policy_document = role(assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]}, policies=[])
        client = AwsVpcClientBuilder().build()
        self.assertFalse(client._is_flow_log_role_compliant(invalid_assume_policy))
        self.assertFalse(client._is_flow_log_role_compliant(invalid_policy_document))
        self.assertFalse(client._is_flow_log_role_compliant(missing_policy_document))

    def test_delivery_role_policy_exists(self) -> None:
        client = AwsVpcClientBuilder()
        expected_policy = policy(name="delivery_role_policy")
        client.with_policies([expected_policy])

        self.assertTrue(client.build()._delivery_role_policy_exists())

    def test_delivery_role_policy_not_found(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_policies([])

        self.assertFalse(client.build()._delivery_role_policy_exists())


class TestAwsFlowLogCompliance(TestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClientBuilder().build()

    def test_flow_log_centralised(self) -> None:
        client = AwsVpcClientBuilder().build()
        self.assertTrue(client._is_flow_log_centralised(flow_log(log_group_name="/vpc/flow_log")))

    def test_flow_log_not_centralised(self) -> None:
        self.assertFalse(self.client()._is_flow_log_centralised(flow_log(log_group_name=None)))
        self.assertFalse(self.client()._is_flow_log_centralised(flow_log(log_group_name="/vpc/something_else")))

    def test_flow_log_not_misconfigured(self) -> None:
        self.assertFalse(self.client()._is_flow_log_misconfigured(flow_log()))
        self.assertFalse(self.client()._is_flow_log_misconfigured(flow_log(log_group_name="/vpc/something_else")))

    def test_flow_log_misconfigured(self) -> None:
        client = AwsVpcClientBuilder().build()
        self.assertTrue(client._is_flow_log_misconfigured(flow_log(status="a")))
        self.assertTrue(client._is_flow_log_misconfigured(flow_log(traffic_type="b")))
        self.assertTrue(client._is_flow_log_misconfigured(flow_log(log_format="c")))
        self.assertTrue(client._is_flow_log_misconfigured(flow_log(deliver_log_role_arn=None)))
        self.assertTrue(client._is_flow_log_misconfigured(flow_log(deliver_log_role_arn="bla")))


class TestVPCFlowLogEnforcementActions(TestCase):
    @staticmethod
    def mock_action(action: Type[ComplianceAction], expected_client: Mock, applied_action: Mock) -> Mock:
        return Mock(spec=action, apply=Mock(side_effect=lambda c: applied_action if c == expected_client else None))

    def test_do_nothing_when_all_correct(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        client.with_roles([role()])
        self.assertEqual(
            [],
            client.build().enforcement_flow_log_actions([vpc()], with_subscription_filter=True),
        )

    def test_create_vpc_flow_logs(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        client.with_roles([role()])

        self.assertEqual(
            [
                create_flow_log_action(vpc_id="vpc-1234"),
            ],
            client.build().enforcement_flow_log_actions([vpc(flow_logs=[])], with_subscription_filter=True),
        )

    def test_vpc_delete_redundant_actions(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        client.with_roles([role()])

        self.assertEqual(
            [
                delete_flow_log_action(flow_log_id="2"),
                delete_flow_log_action(flow_log_id="3"),
            ],
            client.build().enforcement_flow_log_actions(
                [
                    vpc(
                        flow_logs=[
                            flow_log("1"),  # the one we want to keep
                            flow_log("2"),  # duplicate
                            flow_log("3"),  # duplicate
                            flow_log(id="unrelated_flow_log", log_group_name="unrelated flow log"),
                        ]
                    )
                ],
                with_subscription_filter=True,
            ),
        )

    def test_vpc_delete_misconfigured_centralised(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        client.with_roles([role()])

        self.assertEqual(
            [
                delete_flow_log_action(flow_log_id="1"),
                delete_flow_log_action(flow_log_id="3"),
            ],
            client.build().enforcement_flow_log_actions(
                [vpc(flow_logs=[flow_log("1", status="a"), flow_log("2"), flow_log("3")])],
                with_subscription_filter=True,
            ),
        )

    def test_vpc_create_centralised_flow_log(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        client.with_roles([role()])

        self.assertEqual(
            [
                create_flow_log_action(vpc_id="vpc-1"),
            ],
            client.build().enforcement_flow_log_actions(
                [vpc(id="vpc-1", flow_logs=[flow_log(log_group_name="a")])], with_subscription_filter=True
            ),
        )

    def test_vpc_delete_misconfigured_and_create_centralised(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        client.with_roles([role()])

        self.assertEqual(
            [
                delete_flow_log_action(flow_log_id="1"),
                create_flow_log_action(vpc_id="vpc-a"),
            ],
            client.build().enforcement_flow_log_actions(
                [vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])], with_subscription_filter=True
            ),
        )

    def test_create_delivery_role_action_when_role_is_missing(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()

        client.with_roles([])
        client.with_policies([])

        self.assertEqual(
            [create_flow_log_delivery_role_action(iam=client.iam), tag_flow_log_delivery_role_action(iam=client.iam)],
            client.build()._delivery_role_enforcement_actions(),
        )

    def test_delete_and_create_delivery_role_action_when_role_is_missing_and_policy_exists(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()

        client.with_roles([])
        client.with_policies([policy(name="delivery_role_policy")])

        self.assertEqual(
            [
                delete_flow_log_delivery_role_action(iam=client.iam),
                create_flow_log_delivery_role_action(iam=client.iam),
                tag_flow_log_delivery_role_action(iam=client.iam),
            ],
            client.build()._delivery_role_enforcement_actions(),
        )

    def test_delete_and_create_delivery_role_action_when_role_is_not_compliant(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_roles([role(name="vpc_flow_log_role", policies=[])])

        self.assertEqual(
            [
                delete_flow_log_delivery_role_action(iam=client.iam),
                create_flow_log_delivery_role_action(iam=client.iam),
                tag_flow_log_delivery_role_action(iam=client.iam),
            ],
            client.build()._delivery_role_enforcement_actions(),
        )

    def test_tag_flow_log_delivery_role_when_required_tags_missing(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_roles([role(name="vpc_flow_log_role", tags=[tag("unrelated_tag", "some value")])])

        self.assertEqual(
            [tag_flow_log_delivery_role_action(iam=client.iam)],
            client.build()._delivery_role_enforcement_actions(),
        )

    def test_create_central_vpc_log_group_when_missing_with_subscription_filter(self) -> None:

        log_group_config = Config().logs_vpc_flow_log_group_config()

        client = AwsVpcClientBuilder()
        client.with_default_resource_policy()
        client.logs.find_log_group.side_effect = [None]

        actions = client.build().log_group.log_group_enforcement_actions(
            log_group_config=log_group_config, with_subscription_filter=True
        )

        self.assertEqual(
            [
                create_log_group_action(log_group_config=log_group_config, logs=client.logs),
                put_log_group_retention_policy_action(log_group_config, logs=client.logs),
                tag_log_group_action(log_group_config, logs=client.logs),
                put_vpc_log_group_subscription_filter_action(
                    log_group_config=log_group_config,
                    logs=client.logs,
                ),
            ],
            actions,
        )

    def test_create_central_vpc_log_group_without_subscription_filter(self) -> None:
        log_group_config = Config().logs_vpc_flow_log_group_config()

        client = AwsVpcClientBuilder()
        client.with_default_resource_policy()
        client.logs.find_log_group.side_effect = [None]

        actions = client.build().log_group.log_group_enforcement_actions(
            log_group_config=log_group_config, with_subscription_filter=False
        )
        expectedAction = [
            create_log_group_action(log_group_config=log_group_config, logs=client.logs),
            put_log_group_retention_policy_action(
                log_group_config=log_group_config,
                logs=client.logs,
            ),
            tag_log_group_action(log_group_config=log_group_config, logs=client.logs),
        ]
        self.assertEqual(
            expectedAction,
            actions,
        )

    def test_put_subscription_filter_when_central_vpc_log_group_is_not_compliant(self) -> None:

        log_group_config = Config().logs_vpc_flow_log_group_config()

        client = AwsVpcClientBuilder()
        client.with_log_groups([log_group(subscription_filters=[], default_kms_key=True)])
        client.with_default_resource_policy()

        self.assertEqual(
            [
                put_vpc_log_group_subscription_filter_action(log_group_config=log_group_config, logs=client.logs),
            ],
            client.build().log_group.log_group_enforcement_actions(
                log_group_config=log_group_config, with_subscription_filter=True
            ),
        )

    def test_put_retention_policy_when_central_vpc_log_group_does_not_have_one(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([log_group(retention_days=None, default_kms_key=True)])
        client.with_default_resource_policy()
        log_group_config = Config().logs_vpc_flow_log_group_config()
        self.assertEqual(
            [
                put_log_group_retention_policy_action(
                    log_group_config=log_group_config,
                    logs=client.logs,
                ),
            ],
            client.build().log_group.log_group_enforcement_actions(
                log_group_config=log_group_config, with_subscription_filter=True
            ),
        )

    def test_put_retention_policy_when_central_vpc_log_group_retention_differs_from_config(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([log_group(retention_days=21, default_kms_key=True)])
        log_group_config = Config().logs_vpc_flow_log_group_config()
        client.with_default_resource_policy()
        self.assertEqual(
            [
                put_log_group_retention_policy_action(
                    log_group_config=log_group_config,
                    logs=client.logs,
                ),
            ],
            client.build().log_group.log_group_enforcement_actions(
                log_group_config=log_group_config, with_subscription_filter=True
            ),
        )

    def test_tag_vpc_log_group_when_tags_missing(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_resource_policy()
        client.with_log_groups([log_group(tags=[tag("unrelated_tag", "1")], default_kms_key=True)])
        log_group_config = Config().logs_vpc_flow_log_group_config()
        self.assertEqual(
            [
                tag_log_group_action(
                    log_group_config=log_group_config,
                    logs=client.logs,
                ),
            ],
            client.build().log_group.log_group_enforcement_actions(
                log_group_config=log_group_config, with_subscription_filter=True
            ),
        )

    def test_no_central_vpc_log_group_action_when_log_group_is_compliant(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        log_group_config = Config().logs_vpc_flow_log_group_config()
        self.assertEqual(
            [],
            client.build().log_group.log_group_enforcement_actions(
                log_group_config=log_group_config, with_subscription_filter=True
            ),
        )

    def test_delete_subscription_filter_when_exists_and_not_required(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_resource_policy()
        log_group_config = Config().logs_vpc_flow_log_group_config()
        self.assertEqual(
            [delete_vpc_log_group_subscription_filter_action(log_group_config=log_group_config, logs=client.logs)],
            client.build().log_group.log_group_enforcement_actions(
                log_group_config=log_group_config, with_subscription_filter=False
            ),
        )

    def test_no_flow_log_enforcement_actions_required_when_no_vpc_exists(self) -> None:
        client = AwsVpcClientBuilder()
        self.assertEqual([], client.build().enforcement_flow_log_actions(vpcs=[], with_subscription_filter=False))
        self.assertEqual([], client.build().enforcement_flow_log_actions(vpcs=[], with_subscription_filter=True))


class TestDNSEnforcementActions(TestCase):
    def test_new_resources_when_nothing_exists(self) -> None:
        config = Config()
        log_config = config.logs_vpc_dns_log_group_config()

        client = AwsVpcClientBuilder()
        client.with_resource_policy(None)
        client.with_log_groups([None])
        client.with_resolver_query_log_config([])
        client.with_resolver_associations({})
        vpc_client = client.build()
        vpcs = [vpc(id="id1")]

        actual_response = vpc_client.enforcement_dns_log_actions(vpcs, with_subscription_filter=True)
        expected_response = [
            CreateLogGroupAction(logs=vpc_client.logs, log_group_config=log_config),
            PutLogGroupRetentionPolicyAction(logs=vpc_client.logs, log_group_config=log_config),
            TagLogGroupAction(logs=vpc_client.logs, log_group_config=log_config),
            PutLogGroupSubscriptionFilterAction(logs=vpc_client.logs, log_group_config=log_config),
            put_log_group_resource_policy_action(
                log_group_config=Config().logs_route53_query_log_group_config(),
                logs=client.logs,
                policy_document=resource_policy_document(),
            ),
            CreateResolverQueryLogConfig(
                logs=vpc_client.logs,
                resolver=vpc_client.resolver,
                log_group_config=log_config,
                query_log_config_name=config.resolver_dns_query_log_config_name(),
            ),
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id="id1"),
            AssociateResolverQueryLogConfig(
                resolver=vpc_client.resolver, log_config_name=config.resolver_dns_query_log_config_name(), vpcs=vpcs
            ),
        ]
        client.resolver.list_resolver_query_log_configs.assert_called_with(
            query_log_config_name=config.resolver_dns_query_log_config_name()
        )

        self.assertEqual(expected_response, actual_response)

    def test_do_nothing_when_all_correct(self) -> None:
        client = AwsVpcClientBuilder()
        config = Config()
        log_config = config.logs_vpc_dns_log_group_config()
        expected_subscription = expected_subscription_filter(log_config)
        client.with_default_resource_policy()
        client.with_log_groups(
            [
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
            ]
        )
        self.maxDiff = None
        query_log_config = resolver_query_log_config(log_config, config.resolver_dns_query_log_config_name())
        client.with_resolver_query_log_config([query_log_config])
        expected_vpc = vpc()
        client.with_resolver_associations({query_log_config.id: [expected_vpc.id]})
        self.assertEqual(
            [],
            client.build().enforcement_dns_log_actions([expected_vpc], with_subscription_filter=True),
        )

    def test_overwrite_resource_policy_when_incorrect(self) -> None:
        client = AwsVpcClientBuilder()
        config = Config()
        log_config = config.logs_vpc_dns_log_group_config()
        expected_subscription = expected_subscription_filter(log_config)
        client.with_log_groups(
            [
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
            ]
        )
        client.with_resource_policy("the wrong string")
        self.maxDiff = None
        query_log_config = resolver_query_log_config(log_config, config.resolver_dns_query_log_config_name())
        client.with_resolver_query_log_config([query_log_config])
        expected_vpc = vpc()
        client.with_resolver_associations({query_log_config.id: [expected_vpc.id]})
        self.assertEqual(
            [
                put_log_group_resource_policy_action(
                    log_group_config=Config().logs_route53_query_log_group_config(),
                    logs=client.logs,
                    policy_document=resource_policy_document(),
                )
            ],
            client.build().enforcement_dns_log_actions([expected_vpc], with_subscription_filter=True),
        )

    def test_adding_new_vpc(self) -> None:
        client = AwsVpcClientBuilder()
        config = Config()
        log_config = config.logs_vpc_dns_log_group_config()
        expected_subscription = expected_subscription_filter(log_config)
        vpc1 = vpc(id="vpc-1234")
        vpc2 = vpc(id="vpc-5678")
        resolver_config = resolver_query_log_config(
            log_config, config.resolver_dns_query_log_config_name(), "Different-Config-id"
        )

        client.with_resolver_associations({resolver_config.id: [vpc1.id]})
        client.with_default_resource_policy()
        client.with_log_groups(
            [
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
            ]
        )
        client.with_resolver_query_log_config([resolver_config])
        expected_actions = [
            DisassociateResolverQueryLogConfig(resolver=client.resolver, resource_id=vpc2.id),
            AssociateResolverQueryLogConfig(
                resolver=client.resolver,
                log_config_name=config.resolver_dns_query_log_config_name(),
                vpcs=[vpc2],
            ),
        ]
        self.assertEqual(
            expected_actions, client.build().enforcement_dns_log_actions([vpc1, vpc2], with_subscription_filter=True)
        )

    def test_no_dns_enforcement_actions_required_when_no_vpc_exists(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([None])
        client.with_resolver_query_log_config([])
        self.assertEqual([], client.build().enforcement_dns_log_actions(vpcs=[], with_subscription_filter=False))
        self.assertEqual([], client.build().enforcement_dns_log_actions(vpcs=[], with_subscription_filter=True))

    def test_new_resources_when_log_group_name_updated(self) -> None:
        config = Config()
        log_config = config.logs_vpc_dns_log_group_config()
        expected_subscription = expected_subscription_filter(log_config)
        client = AwsVpcClientBuilder()
        client.with_resource_policy("the wrong string")
        client.with_log_groups(
            [
                None,
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn="new_log_group_arn",
                ),
            ]
        )
        client.with_resolver_query_log_config(
            [resolver_query_log_config(log_config, config.resolver_dns_query_log_config_name())]
        )
        client.with_resolver_associations({})
        vpc_client = client.build()

        actual_response = vpc_client.enforcement_dns_log_actions(
            [vpc(id="vpc-1234"), vpc(id="vpc-5678")], with_subscription_filter=True
        )
        expected_response = [
            CreateLogGroupAction(logs=vpc_client.logs, log_group_config=log_config),
            PutLogGroupRetentionPolicyAction(logs=vpc_client.logs, log_group_config=log_config),
            TagLogGroupAction(logs=vpc_client.logs, log_group_config=log_config),
            PutLogGroupSubscriptionFilterAction(logs=vpc_client.logs, log_group_config=log_config),
            put_log_group_resource_policy_action(
                log_group_config=Config().logs_route53_query_log_group_config(),
                logs=client.logs,
                policy_document=resource_policy_document(),
            ),
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id="vpc-1234"),
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id="vpc-5678"),
            DeleteResolverQueryLogConfig(resolver=vpc_client.resolver, query_log_config_id="some-id"),
            CreateResolverQueryLogConfig(
                logs=vpc_client.logs,
                resolver=vpc_client.resolver,
                log_group_config=log_config,
                query_log_config_name=config.resolver_dns_query_log_config_name(),
            ),
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id="vpc-1234"),
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id="vpc-5678"),
            AssociateResolverQueryLogConfig(
                resolver=vpc_client.resolver,
                log_config_name=config.resolver_dns_query_log_config_name(),
                vpcs=[vpc(id="vpc-1234"), vpc(id="vpc-5678")],
            ),
        ]

        client.resolver.list_resolver_query_log_configs.assert_called_with(
            query_log_config_name=config.resolver_dns_query_log_config_name()
        )

        self.assertEqual(expected_response, actual_response)

    def test_association_of_vpc_with_another_association(self) -> None:
        config = Config()
        log_config = config.logs_vpc_dns_log_group_config()
        expected_subscription = expected_subscription_filter(log_config)
        client = AwsVpcClientBuilder()
        client.with_default_resource_policy()
        client.with_log_groups(
            [
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
                log_group(
                    subscription_filters=[expected_subscription],
                    name=log_config.logs_group_name,
                    retention_days=log_config.logs_group_retention_policy_days,
                    arn=log_config.logs_log_group_destination,
                ),
            ]
        )

        vpcs = [vpc(id="vpc-1234"), vpc(id="vpc-5678")]

        client.with_resolver_query_log_config(
            [resolver_query_log_config(log_config, config.resolver_dns_query_log_config_name())]
        )
        other_config = resolver_query_log_config(log_config, "Different-Config-name", "Different-Config-id")
        client.with_resolver_associations(
            {
                other_config.id: [vpcs[1].id],
            }
        )
        vpc_client = client.build()

        expected_response = [
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id=vpcs[0].id),
            DisassociateResolverQueryLogConfig(resolver=vpc_client.resolver, resource_id=vpcs[1].id),
            AssociateResolverQueryLogConfig(
                resolver=vpc_client.resolver,
                log_config_name=config.resolver_dns_query_log_config_name(),
                vpcs=vpcs,
            ),
        ]

        actual_response = vpc_client.enforcement_dns_log_actions(vpcs, with_subscription_filter=True)

        self.maxDiff = None
        self.assertEqual(expected_response, actual_response)


class TestLogGroupCompliance(TestCase):
    def test_central_vpc_log_group(self) -> None:
        log_group_config = Config().logs_vpc_flow_log_group_config()
        self.assertTrue(
            AwsLogsClient(Mock(), Mock(), account=account()).is_central_log_group(
                log_group=log_group(
                    name="/vpc/flow_log",
                    subscription_filters=[
                        subscription_filter(
                            filter_pattern="[version, account_id, interface_id]",
                            destination_arn="arn:aws:logs:::destination:central",
                        )
                    ],
                ),
                log_group_config=log_group_config,
            )
        )

    def test_log_group_is_not_vpc_central(self) -> None:
        client = AwsLogsClient(Mock(), Mock(), account=account())
        config = Config()
        self.assertFalse(
            client.is_central_log_group(
                log_group=log_group(name="/vpc/something_else"),
                log_group_config=config.logs_vpc_flow_log_group_config(),
            )
        )
        self.assertFalse(
            client.is_central_log_group(
                log_group=log_group(subscription_filters=[]), log_group_config=config.logs_vpc_flow_log_group_config()
            )
        )
        self.assertFalse(
            client.is_central_log_group(
                log_group=log_group(subscription_filters=[subscription_filter(filter_pattern="something")]),
                log_group_config=config.logs_vpc_flow_log_group_config(),
            )
        )
        self.assertFalse(
            client.is_central_log_group(
                log_group=log_group(subscription_filters=[subscription_filter(destination_arn="somewhere")]),
                log_group_config=config.logs_vpc_flow_log_group_config(),
            )
        )


class AwsVpcClientBuilder(TestCase):
    def __init__(self) -> None:
        super().__init__()
        self.ec2 = Mock(spec=AwsEC2Client, wraps=AwsEC2Client(Mock()))
        self.iam = Mock(spec=AwsIamClient, wraps=AwsIamClient(Mock()))
        self.logs = Mock(spec=AwsLogsClient, wraps=AwsLogsClient(boto_logs=Mock(), kms=Mock(), account=account()))
        self.config = Config()
        self.log_group = AwsLogGroupClient(logs=self.logs)
        self.resolver = Mock(spec=AwsResolverClient, wraps=AwsResolverClient(Mock()))

    def with_default_vpc(self) -> AwsVpcClientBuilder:
        vpcs = [
            vpc(id="default-log-group-1", flow_logs=[flow_log(deliver_log_role_arn=None)]),
            vpc(id="default-log-group-2", flow_logs=[flow_log(log_group_name=None)]),
        ]
        self.ec2.list_vpcs.return_value = vpcs
        return self

    def with_default_key(self) -> AwsVpcClientBuilder:

        return self

    def with_default_log_group(self) -> AwsVpcClientBuilder:
        self.with_log_groups([log_group(kms_key_id=key().id)])
        return self

    def with_log_groups(self, log_groups: Sequence[Optional[LogGroup]]) -> AwsVpcClientBuilder:
        self.logs.find_log_group.side_effect = log_groups
        return self

    def with_resolver_associations(self, association: Dict[str, List[str]]) -> AwsVpcClientBuilder:
        def query_log_config_association_exists(vpc_id: str, resolver_query_log_config_id: str) -> bool:
            return vpc_id in association.get(resolver_query_log_config_id, [])

        def get_vpc_query_log_config_association(vpc_id: str) -> Optional[str]:
            for confid_id, vpcs in association.items():
                if vpc_id in vpcs:
                    return confid_id
            return None

        self.resolver.query_log_config_association_exists.side_effect = query_log_config_association_exists
        self.resolver.get_vpc_query_log_config_association.side_effect = get_vpc_query_log_config_association
        return self

    def with_roles(self, roles: Sequence[Role]) -> AwsVpcClientBuilder:
        def get_role(name: str) -> Optional[Role]:
            result = next(filter(lambda a_role: a_role.name == name, roles), None)
            if result is None:
                raise IamException(f"cannot find {name} in {roles}")

            return result

        def find_role_by_name(name: str) -> Optional[Role]:
            result = filter(lambda role: role.name == name, roles)
            return next(result, None)

        def find_role_by_arn(arn: str) -> Optional[Role]:
            result = filter(lambda role: role.arn == arn, roles)
            return next(result, None)

        self.iam.get_role.side_effect = get_role
        self.iam.find_role.side_effect = find_role_by_name
        self.iam.find_role_by_arn.side_effect = find_role_by_arn

        return self

    def with_policies(self, policies: Sequence[Policy]) -> AwsVpcClientBuilder:
        def find_policy_arn(name: str) -> Optional[str]:
            result = next(filter(lambda p: p.name == name, policies), None)
            return result.arn if result else None

        self.iam.find_policy_arn.side_effect = find_policy_arn
        return self

    def build(self) -> AwsVpcClient:
        return AwsVpcClient(
            ec2=self.ec2,
            iam=self.iam,
            logs=self.logs,
            config=self.config,
            log_group=self.log_group,
            resolver=self.resolver,
        )

    def with_create_role(self, expected_role: Role) -> AwsVpcClientBuilder:
        def create_role(name: str, assume_policy: Dict[str, Any]) -> Role:
            self.assertEqual(expected_role.name, name, "The expected mocked role name did not match what was called")
            self.assertEqual(
                expected_role.assume_policy,
                assume_policy,
                "The expected mocked role assume_policy did not match what was called",
            )
            return expected_role

        self.iam.create_role.side_effect = create_role
        return self

    def with_create_policies(self, expected_policies: Sequence[Policy]) -> AwsVpcClientBuilder:
        def create_policy(name: str, document: Dict[str, Any]) -> Policy:
            found_policies: Sequence[Policy] = list(filter(lambda p: p.name == name, expected_policies))
            self.assertTrue(
                len(found_policies) == 1,
                f"did not find a unique policy with name '{name}' in expected policies {expected_policies}",
            )
            found_policy: Policy = next(iter(found_policies))

            self.assertEqual(
                found_policy.document, document, "The expected mocked policy document did not match what was called"
            )
            return found_policy

        self.iam.create_policy.side_effect = create_policy
        return self

    def with_attach_role_policy(self, expected_role: Role) -> AwsVpcClientBuilder:
        def attach_role_policy(role: Role, policy_arn: str) -> None:
            self.assertEqual(role.name, expected_role.name)
            self.assertIn(policy_arn, [p.arn for p in expected_role.policies])
            return None

        self.iam.attach_role_policy.side_effect = attach_role_policy
        return self

    def with_create_flow_logs(self) -> AwsVpcClientBuilder:
        self.ec2.create_flow_logs.return_value = None
        return self

    def with_resolver_query_log_config(
        self, resolver_query_log_config: List[ResolverQueryLogConfig]
    ) -> AwsVpcClientBuilder:
        def list_resolver_query_log_configs(query_log_config_name: str) -> List[ResolverQueryLogConfig]:
            return resolver_query_log_config

        self.resolver.list_resolver_query_log_configs.side_effect = list_resolver_query_log_configs
        return self

    def with_resource_policy(self, policy):
        def get_resource_policy(policy_name: str) -> Optional[str]:
            return policy

        self.logs.get_resource_policy.side_effect = get_resource_policy
        return self

    def with_default_resource_policy(self):
        self.with_resource_policy(self.logs.logs_resource_policy_document())
        return self
