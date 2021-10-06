from __future__ import annotations

from typing import Sequence, Optional, Type, Dict, Any

from src.data.aws_iam_types import Role, Policy
from src.data.aws_kms_types import Key
from src.data.aws_logs_types import LogGroup
from src.data.aws_scanner_exceptions import IamException
from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_compliance_actions import (
    ComplianceAction,
)

from tests.test_types_generator import (
    alias,
    compliant_key_policy,
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    create_log_group_kms_key_action,
    create_vpc_log_group_action,
    delete_flow_log_action,
    delete_flow_log_delivery_role_action,
    delete_log_group_kms_key_alias_action,
    flow_log,
    key,
    log_group,
    policy,
    put_vpc_log_group_subscription_filter_action,
    role,
    subscription_filter,
    update_log_group_kms_key_action,
    vpc,
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
        client.with_default_log_group()
        client.with_default_key()
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
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]})],
        )
        client = AwsVpcClientBuilder().build()
        self.assertTrue(client._is_flow_log_role_compliant(delivery_role))

    def test_flow_log_role_not_compliant(self) -> None:
        invalid_assume_policy = role(
            assume_policy={"Statement": [{"Action": "sts:other"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]})],
        )
        invalid_policy_document = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:bla"]}]})],
        )
        missing_policy_document = role(assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]}, policies=[])
        client = AwsVpcClientBuilder().build()
        self.assertFalse(client._is_flow_log_role_compliant(invalid_assume_policy))
        self.assertFalse(client._is_flow_log_role_compliant(invalid_policy_document))
        self.assertFalse(client._is_flow_log_role_compliant(missing_policy_document))

    def test_delivery_role_policy_exists(self) -> None:
        client = AwsVpcClientBuilder()
        expected_policy = policy(name="vpc_flow_log_role_policy")
        client.with_policies([expected_policy])

        self.assertTrue(client.build()._delivery_role_policy_exists())

    def test_delivery_role_policy_not_found(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_policies([])

        self.assertFalse(client.build()._delivery_role_policy_exists())


class TestAwsKmsKeyCompliance(TestCase):
    def test_create_kms_if_not_exists(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_no_alias()

        self.assertEqual([create_log_group_kms_key_action(kms=client.kms)], client.build()._kms_enforcement_actions())

    def test_recreate_alias_and_key_when_incorrect_policy(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_default_key()

        self.assertEqual(
            [delete_log_group_kms_key_alias_action(kms=client.kms), create_log_group_kms_key_action(kms=client.kms)],
            client.build()._kms_enforcement_actions(),
        )


class TestAwsFlowLogCompliance(TestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClientBuilder().build()

    def test_flow_log_centralised(self) -> None:
        self.assertTrue(self.client()._is_flow_log_centralised(flow_log(log_group_name="/vpc/flow_log")))

    def test_flow_log_not_centralised(self) -> None:
        self.assertFalse(self.client()._is_flow_log_centralised(flow_log(log_group_name=None)))
        self.assertFalse(self.client()._is_flow_log_centralised(flow_log(log_group_name="/vpc/something_else")))

    def test_flow_log_not_misconfigured(self) -> None:
        self.assertFalse(self.client()._is_flow_log_misconfigured(flow_log()))
        self.assertFalse(self.client()._is_flow_log_misconfigured(flow_log(log_group_name="/vpc/something_else")))

    def test_flow_log_misconfigured(self) -> None:
        self.assertTrue(self.client()._is_flow_log_misconfigured(flow_log(status="a")))
        self.assertTrue(self.client()._is_flow_log_misconfigured(flow_log(traffic_type="b")))
        self.assertTrue(self.client()._is_flow_log_misconfigured(flow_log(log_format="c")))
        self.assertTrue(self.client()._is_flow_log_misconfigured(flow_log(deliver_log_role_arn=None)))
        self.assertTrue(self.client()._is_flow_log_misconfigured(flow_log(deliver_log_role_arn="bla")))


class TestAwsEnforcementActions(TestCase):
    @staticmethod
    def mock_action(action: Type[ComplianceAction], expected_client: Mock, applied_action: Mock) -> Mock:
        return Mock(spec=action, apply=Mock(side_effect=lambda c: applied_action if c == expected_client else None))

    def test_do_nothing_when_all_correct(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual([], client.build().enforcement_actions([vpc()]))

    def test_flow_logs_are_notified_of_kms_changes(self) -> None:
        expected_key = key()
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual(
            [
                delete_log_group_kms_key_alias_action(kms=client.kms),
                create_log_group_kms_key_action(kms=client.kms),
                update_log_group_kms_key_action(logs=client.logs, kms=client.kms),
            ],
            client.build().enforcement_actions([vpc()]),
        )

    def test_create_vpc_flow_logs(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual(
            [create_flow_log_action(vpc_id="vpc-1234")],
            client.build().enforcement_actions([vpc(flow_logs=[])]),
        )

    def test_vpc_delete_redundant_centralised(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual(
            [delete_flow_log_action(flow_log_id="2"), delete_flow_log_action(flow_log_id="3")],
            client.build().enforcement_actions(
                [
                    vpc(
                        flow_logs=[
                            flow_log("1"),  # the one we want to keep
                            flow_log("2"),  # duplicate
                            flow_log("3"),  # duplicate
                            flow_log(id="unrelated_flow_log", log_group_name="unrelated flow log"),
                        ]
                    )
                ]
            ),
        )

    def test_vpc_delete_misconfigured_centralised(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual(
            [delete_flow_log_action(flow_log_id="1"), delete_flow_log_action(flow_log_id="3")],
            client.build().enforcement_actions(
                [vpc(flow_logs=[flow_log("1", status="a"), flow_log("2"), flow_log("3")])]
            ),
        )

    def test_vpc_create_centralised(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual(
            [create_flow_log_action(vpc_id="vpc-1")],
            client.build().enforcement_actions([vpc(id="vpc-1", flow_logs=[flow_log(log_group_name="a")])]),
        )

    def test_vpc_delete_misconfigured_and_create_centralised(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role()])

        self.assertEqual(
            [delete_flow_log_action(flow_log_id="1"), create_flow_log_action(vpc_id="vpc-a")],
            client.build().enforcement_actions([vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])]),
        )

    def test_create_delivery_role_action_when_role_is_missing(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()

        client.with_roles([])
        client.with_policies([])

        self.assertEqual([create_flow_log_delivery_role_action()], client.build()._delivery_role_enforcement_actions())

    def test_delete_and_create_delivery_role_action_when_role_is_missing_and_policy_exists(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()

        client.with_roles([])
        client.with_policies([policy(name="vpc_flow_log_role_policy")])

        self.assertEqual(
            [delete_flow_log_delivery_role_action(iam=client.iam), create_flow_log_delivery_role_action()],
            client.build()._delivery_role_enforcement_actions(),
        )

    def test_delete_and_create_delivery_role_action_when_role_is_not_compliant(self) -> None:
        expected_key = key(policy=compliant_key_policy())
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_key(expected_key)
        client.with_default_log_group()
        client.with_roles([role(name="vpc_flow_log_role", policies=[])])

        self.assertEqual(
            [delete_flow_log_delivery_role_action(iam=client.iam), create_flow_log_delivery_role_action()],
            client.build()._delivery_role_enforcement_actions(),
        )

    def test_create_central_vpc_log_group_when_missing_with_subscription_filter_and_kms_key(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([])
        client.with_default_alias()
        client.with_default_key()

        actions = client.build()._vpc_log_group_enforcement_actions(kms_key_updated=False)

        self.assertEqual(
            [
                create_vpc_log_group_action(logs=client.logs),
                put_vpc_log_group_subscription_filter_action(logs=client.logs),
                update_log_group_kms_key_action(logs=client.logs, kms=client.kms),
            ],
            actions,
        )
        self.assertEqual(3, len(actions))

    def test_put_subscription_filter_when_central_vpc_log_group_is_not_compliant(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([log_group(subscription_filters=[], default_kms_key=True)])
        client.with_default_key()

        self.assertEqual(
            [put_vpc_log_group_subscription_filter_action(logs=client.logs)],
            client.build()._vpc_log_group_enforcement_actions(kms_key_updated=False),
        )

    def test_update_kms_key_when_kms_is_updated(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([log_group(default_kms_key=True)])
        client.with_default_key()

        self.assertEqual(
            [update_log_group_kms_key_action(logs=client.logs, kms=client.kms)],
            client.build()._vpc_log_group_enforcement_actions(kms_key_updated=True),
        )

    def test_update_kms_key_when_kms_is_not_set(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_log_groups([log_group(default_kms_key=False)])
        client.with_default_key()

        self.assertEqual(
            [update_log_group_kms_key_action(logs=client.logs, kms=client.kms)],
            client.build()._vpc_log_group_enforcement_actions(kms_key_updated=False),
        )

    def test_no_central_vpc_log_group_action_when_log_group_is_compliant(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_log_group()
        client.with_default_key()

        self.assertEqual([], client.build()._vpc_log_group_enforcement_actions(kms_key_updated=False))


class TestLogGroupCompliance(TestCase):
    def test_central_vpc_log_group(self) -> None:
        self.assertTrue(
            AwsVpcClientBuilder()
            .build()
            ._is_central_vpc_log_group(
                log_group(
                    name="/vpc/flow_log",
                    subscription_filters=[
                        subscription_filter(
                            filter_pattern="[version, account_id, interface_id]",
                            destination_arn="arn:aws:logs:::destination:central",
                        )
                    ],
                )
            )
        )

    def test_log_group_is_not_vpc_central(self) -> None:
        client = AwsVpcClientBuilder().build()
        self.assertFalse(client._is_central_vpc_log_group(log_group(name="/vpc/something_else")))
        self.assertFalse(client._is_central_vpc_log_group(log_group(subscription_filters=[])))
        self.assertFalse(
            client._is_central_vpc_log_group(
                log_group(subscription_filters=[subscription_filter(filter_pattern="something")])
            )
        )
        self.assertFalse(
            client._is_central_vpc_log_group(
                log_group(subscription_filters=[subscription_filter(destination_arn="somewhere")])
            )
        )


class AwsVpcClientBuilder(TestCase):
    def __init__(self) -> None:
        super().__init__()
        self.ec2 = Mock(spec=AwsEC2Client, wraps=AwsEC2Client(Mock()))
        self.iam = Mock(spec=AwsIamClient, wraps=AwsIamClient(Mock()))
        self.logs = Mock(spec=AwsLogsClient, wraps=AwsLogsClient(Mock()))
        self.kms = Mock(spec=AwsKmsClient, wraps=AwsKmsClient(Mock()))

    def with_default_vpc(self) -> AwsVpcClientBuilder:
        vpcs = [
            vpc(id="default-log-group-1", flow_logs=[flow_log(deliver_log_role_arn=None)]),
            vpc(id="default-log-group-2", flow_logs=[flow_log(log_group_name=None)]),
        ]
        self.ec2.list_vpcs.return_value = vpcs
        return self

    def with_default_alias(self) -> AwsVpcClientBuilder:
        self.kms.get_alias.return_value = alias()
        self.kms.find_alias.return_value = alias()
        return self

    def with_no_alias(self) -> AwsVpcClientBuilder:
        self.kms.find_alias.return_value = None
        return self

    def with_default_key(self) -> AwsVpcClientBuilder:
        self.with_key(key())
        return self

    def with_key(self, key: Key) -> AwsVpcClientBuilder:
        self.kms.get_key.side_effect = lambda k: key if k == key.id else self.fail(f"expected {key.id}, got {k}")
        return self

    def with_default_log_group(self) -> AwsVpcClientBuilder:
        self.with_log_groups([log_group(kms_key_id=key().id)])
        return self

    def with_log_groups(self, log_groups: Sequence[LogGroup]) -> AwsVpcClientBuilder:
        def describe_log_groups(name_prefix: str) -> Sequence[LogGroup]:
            return list(filter(lambda log_group: log_group.name.startswith(name_prefix), log_groups))

        self.logs.describe_log_groups.side_effect = describe_log_groups
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
        def find_policy_arn(name: str) -> Optional[Policy]:
            result = filter(lambda role: role.name == name, policies)
            return next(result, None)

        self.iam.find_policy_arn.side_effect = find_policy_arn
        return self

    def build(self) -> AwsVpcClient:
        return AwsVpcClient(self.ec2, self.iam, self.logs, self.kms)

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
        def attach_role_policy(role: Role, policy: Policy) -> None:
            self.assertEqual(role.name, expected_role.name)
            self.assertIn(policy, expected_role.policies)
            return None

        self.iam.attach_role_policy.side_effect = attach_role_policy
        return self

    def with_create_flow_logs(self) -> AwsVpcClientBuilder:
        self.ec2.create_flow_logs.return_value = None
        return self
