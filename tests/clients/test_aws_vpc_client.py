from __future__ import annotations

from typing import Sequence, Optional

from src.data.aws_iam_types import Role, Policy
from src.data.aws_kms_types import Key
from src.data.aws_scanner_exceptions import IamException
from tests import _raise
from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest import TestCase
from unittest.mock import Mock, patch

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_compliance_actions import (
    CreateVpcLogGroupAction,
    CreateFlowLogAction,
    CreateFlowLogDeliveryRoleAction,
    DeleteFlowLogAction,
    DeleteFlowLogDeliveryRoleAction,
    PutVpcLogGroupSubscriptionFilterAction,
    CreateLogGroupKmsKeyAction,
    DeleteLogGroupKmsKeyAliasAction,
    UpdateLogGroupKmsKeyAction,
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


class TestAwsVpcClient(AwsScannerTestCase):
    def test_list_vpcs(self) -> None:
        a_key = key()
        log_role = role(arn=flow_log().deliver_log_role_arn)
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
        client.with_roles([role(), role(arn=flow_log().deliver_log_role_arn)])

        enriched = client.build().list_vpcs()
        self.assertEqual(len(enriched), 2)
        self.assertEqual(expected_enriched_vpcs, enriched)


class TestAwsLogDeliveryRoleCompliance(AwsScannerTestCase):
    def test_find_flow_log_delivery_role(self) -> None:
        delivery_role = role(name="vpc_flow_log_role")
        client = AwsVpcClientBuilder().with_roles([delivery_role])

        self.assertEqual(delivery_role, client.build()._find_flow_log_delivery_role())

    def test_get_flow_log_delivery_role_arn(self) -> None:
        delivery_role = role(arn="arn:aws:iam::112233445566:role/a_role")
        client = AwsVpcClientBuilder().with_roles([delivery_role])

        self.assertEqual(delivery_role.arn, client.build()._get_flow_log_delivery_role_arn())

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
        client.with_policy([expected_policy])

        self.assertTrue(client.build()._delivery_role_policy_exists())

    def test_delivery_role_policy_not_found(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_policy([])

        self.assertFalse(client.build()._delivery_role_policy_exists())


class TestAwsKmsKeyCompliance(AwsScannerTestCase):
    def test_create_kms_if_not_exists(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_no_alias()

        self.assertEqual([create_log_group_kms_key_action()], client.build()._kms_enforcement_actions())

    def test_recreate_alias_and_key_when_incorrect_policy(self) -> None:
        client = AwsVpcClientBuilder()
        client.with_default_alias()
        client.with_default_key()

        self.assertEqual(
            [delete_log_group_kms_key_alias_action(), create_log_group_kms_key_action()],
            client.build()._kms_enforcement_actions(),
        )


class TestAwsFlowLogCompliance(AwsScannerTestCase):
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


class TestAwsEnforcementActions(AwsScannerTestCase):
    @staticmethod
    def mock_action(action, expected_client, applied_action) -> Mock:
        return Mock(spec=action, apply=Mock(side_effect=lambda c: applied_action if c == expected_client else None))

    def test_apply_actions(self) -> None:
        ec2, iam, logs, kms = Mock(), Mock(), Mock(), Mock()
        applied = [Mock(name=f"applied_action_{i}") for i in range(9)]
        actions = [
            self.mock_action(CreateVpcLogGroupAction, logs, applied[0]),
            self.mock_action(CreateFlowLogAction, ec2, applied[1]),
            self.mock_action(CreateFlowLogDeliveryRoleAction, iam, applied[2]),
            self.mock_action(UpdateLogGroupKmsKeyAction, logs, applied[3]),
            self.mock_action(DeleteFlowLogAction, ec2, applied[4]),
            self.mock_action(DeleteFlowLogDeliveryRoleAction, iam, applied[5]),
            self.mock_action(PutVpcLogGroupSubscriptionFilterAction, logs, applied[6]),
            self.mock_action(CreateLogGroupKmsKeyAction, kms, applied[7]),
            self.mock_action(DeleteLogGroupKmsKeyAliasAction, kms, applied[8]),
        ]
        self.assertEqual(applied, AwsVpcClient(ec2, iam, logs, kms).apply(actions))

    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClientBuilder().build()

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
                DeleteLogGroupKmsKeyAliasAction(),
                CreateLogGroupKmsKeyAction(),
                UpdateLogGroupKmsKeyAction(kms_key_arn_resolver=lambda: expected_key.arn),
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
            [
                CreateFlowLogAction(
                    vpc_id="vpc-1234",
                    log_group_name="/vpc/flow_log",
                    permission_resolver=lambda: "arn:aws:iam::112233445566:role/a_role",
                )
            ],
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
            [delete_flow_log_action("2"), delete_flow_log_action("3")],
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
            [delete_flow_log_action("1"), delete_flow_log_action("3")],
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
            [create_flow_log_action("vpc-1")],
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
            [delete_flow_log_action("1"), create_flow_log_action("vpc-a")],
            client.build().enforcement_actions([vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])]),
        )

    def test_create_delivery_role_action_when_role_is_missing(self) -> None:
        with patch.object(AwsVpcClient, "_find_flow_log_delivery_role", return_value=None):
            with patch.object(AwsVpcClient, "_delivery_role_policy_exists", return_value=False):
                self.assertEqual(
                    [create_flow_log_delivery_role_action()], self.client()._delivery_role_enforcement_actions()
                )

    def test_delete_and_create_delivery_role_action_when_role_is_missing_and_policy_exists(self) -> None:
        with patch.object(AwsVpcClient, "_find_flow_log_delivery_role", return_value=None):
            with patch.object(AwsVpcClient, "_delivery_role_policy_exists", return_value=True):
                self.assertEqual(
                    [delete_flow_log_delivery_role_action(), create_flow_log_delivery_role_action()],
                    self.client()._delivery_role_enforcement_actions(),
                )

    def test_delete_and_create_delivery_role_action_when_role_is_not_compliant(self) -> None:
        non_compliant_role = role(name="non_compliant")
        with patch.object(AwsVpcClient, "_is_flow_log_role_compliant", side_effect=lambda r: r != non_compliant_role):
            with patch.object(AwsVpcClient, "_find_flow_log_delivery_role", return_value=non_compliant_role):
                self.assertEqual(
                    [delete_flow_log_delivery_role_action(), create_flow_log_delivery_role_action()],
                    self.client()._delivery_role_enforcement_actions(),
                )

    def test_create_central_vpc_log_group_with_subscription_filter_and_kms_key_when_missing(self) -> None:
        with patch.object(AwsVpcClient, "_get_kms_key_arn", return_value=key().arn):
            with patch.object(AwsVpcClient, "_find_log_group", return_value=None) as find_log_group:
                actions = self.client()._vpc_log_group_enforcement_actions(kms_key_updated=False)

        self.assertEqual(
            [
                create_vpc_log_group_action(),
                put_vpc_log_group_subscription_filter_action(),
                update_log_group_kms_key_action(),
            ],
            actions,
        )
        find_log_group.assert_called_once_with("/vpc/flow_log")
        self.assertEqual(3, len(actions))
        self.assertEqual(key().arn, actions[2].kms_key_arn_resolver())

    def test_put_subscription_filter_when_central_vpc_log_group_is_not_compliant(self) -> None:
        with patch.object(
            AwsVpcClient, "_find_log_group", return_value=log_group(subscription_filters=[], default_kms_key=True)
        ):
            self.assertEqual(
                [put_vpc_log_group_subscription_filter_action()],
                self.client()._vpc_log_group_enforcement_actions(kms_key_updated=False),
            )

    def test_update_kms_key_when_kms_is_updated(self) -> None:
        with patch.object(AwsVpcClient, "_find_log_group", return_value=log_group(default_kms_key=True)):
            self.assertEqual(
                [update_log_group_kms_key_action()],
                self.client()._vpc_log_group_enforcement_actions(kms_key_updated=True),
            )

    def test_update_kms_key_when_kms_is_not_set(self) -> None:
        with patch.object(AwsVpcClient, "_find_log_group", return_value=log_group(default_kms_key=False)):
            self.assertEqual(
                [update_log_group_kms_key_action()],
                self.client()._vpc_log_group_enforcement_actions(kms_key_updated=False),
            )

    def test_no_central_vpc_log_group_action_when_log_group_is_compliant(self) -> None:
        client = AwsVpcClientBuilder().with_default_log_group().build()
        self.assertEqual([], client._vpc_log_group_enforcement_actions(kms_key_updated=False))


class TestLogGroupCompliance(AwsScannerTestCase):
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

    def test_get_kms_key_arn(self) -> None:
        client = AwsVpcClientBuilder().with_default_alias().with_default_key().build()
        self.assertEqual(key().arn, client._get_kms_key_arn())


class AwsVpcClientBuilder(TestCase):
    def __init__(self) -> None:
        super().__init__()
        self.ec2 = Mock(spec=AwsEC2Client)
        self.iam = Mock(spec=AwsIamClient)
        self.logs = Mock(spec=AwsLogsClient)
        self.kms = Mock(spec=AwsKmsClient)

    def with_default_vpc(self):
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
        lg = log_group(kms_key_id=key().id)
        self.logs.describe_log_groups.side_effect = (
            lambda n: [lg] if n == lg.name else self.fail(f"expected {lg.name}, got {n}")
        )
        return self

    def with_roles(self, roles: Sequence[Role]) -> AwsVpcClientBuilder:
        def get_role(name: str) -> Optional[Role]:
            return next(filter(lambda role: role.name == name, roles), None) or _raise(
                IamException(f"cannot find {name} in {roles}")
            )

        def find_role_by_name(name: str) -> Optional[Role]:
            return next(filter(lambda role: role.name == name, roles), None)

        def find_role_by_arn(arn: str) -> Optional[Role]:
            return next(filter(lambda role: role.arn == arn, roles), None)

        self.iam.get_role.side_effect = get_role
        self.iam.find_role.side_effect = find_role_by_name
        self.iam.find_role_by_arn.side_effect = find_role_by_arn

        return self

    def with_policy(self, policies: Sequence[Policy]):
        def find_policy_arn(name: str) -> Optional[Policy]:
            return next(filter(lambda role: role.name == name, policies), None)

        self.iam.find_policy_arn.side_effect = find_policy_arn

    def build(self) -> AwsVpcClient:
        return AwsVpcClient(self.ec2, self.iam, self.logs, self.kms)
