from tests.aws_scanner_test_case import AwsScannerTestCase
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
)

from tests.test_types_generator import (
    create_vpc_log_group_action,
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    delete_flow_log_action,
    delete_flow_log_delivery_role_action,
    flow_log,
    key,
    log_group,
    policy,
    put_vpc_log_group_subscription_filter_action,
    role,
    subscription_filter,
    vpc,
)


class TestAwsVpcClient(AwsScannerTestCase):
    def test_list_vpcs(self) -> None:
        log_role = role(name="a_log_role")
        a_key = key(id="the_key")
        group = log_group(name="a_log_group", kms_key_id=a_key.id)
        vpcs = [vpc(flow_logs=[flow_log(deliver_log_role_arn=None)]), vpc(flow_logs=[flow_log(log_group_name=None)])]
        client = AwsVpcClient(
            Mock(list_vpcs=Mock(return_value=vpcs)),
            Mock(find_role_by_arn=Mock(side_effect=lambda a: log_role if a == ":role/vpc_flow_log_role" else None)),
            Mock(describe_log_groups=Mock(side_effect=lambda n: [group] if n == "/vpc/flow_log" else None)),
            Mock(get_key=Mock(side_effect=lambda k: a_key if k == a_key.id else None)),
        )
        enriched = client.list_vpcs()
        self.assertEqual(vpcs, enriched)
        self.assertEqual([None, log_role], [fl.deliver_log_role for v in vpcs for fl in v.flow_logs])
        self.assertEqual([group, None], [fl.log_group for v in vpcs for fl in v.flow_logs])
        self.assertEqual([a_key], [fl.log_group.kms_key for v in vpcs for fl in v.flow_logs if fl.log_group])


class TestAwsLogDeliveryRoleCompliance(AwsScannerTestCase):
    def test_find_flow_log_delivery_role(self) -> None:
        delivery_role = role(name="the_delivery_role")
        ec2, iam, logs, kms = Mock(), Mock(), Mock(), Mock()
        with patch.object(iam, "find_role", side_effect=lambda n: delivery_role if n == "vpc_flow_log_role" else None):
            self.assertEqual(delivery_role, AwsVpcClient(ec2, iam, logs, kms)._find_flow_log_delivery_role())

    def test_get_flow_log_delivery_role_arn(self) -> None:
        delivery_role = role(arn="the_arn")
        ec2, iam, logs, kms = Mock(), Mock(), Mock(), Mock()
        with patch.object(iam, "get_role", side_effect=lambda n: delivery_role if n == "vpc_flow_log_role" else None):
            self.assertEqual("the_arn", AwsVpcClient(ec2, iam, logs, kms)._get_flow_log_delivery_role_arn())

    def test_flow_log_role_compliant(self) -> None:
        delivery_role = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]})],
        )
        ec2, iam, logs, kms = Mock(), Mock(), Mock(), Mock()
        self.assertTrue(AwsVpcClient(ec2, iam, logs, kms)._is_flow_log_role_compliant(delivery_role))

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
        ec2, iam, logs, kms = Mock(), Mock(), Mock(), Mock()
        self.assertFalse(AwsVpcClient(ec2, iam, logs, kms)._is_flow_log_role_compliant(invalid_assume_policy))
        self.assertFalse(AwsVpcClient(ec2, iam, logs, kms)._is_flow_log_role_compliant(invalid_policy_document))
        self.assertFalse(AwsVpcClient(ec2, iam, logs, kms)._is_flow_log_role_compliant(missing_policy_document))

    def test_delivery_role_policy_exists(self) -> None:
        client = AwsVpcClient(AwsEC2Client(Mock()), AwsIamClient(Mock()), AwsLogsClient(Mock()), AwsKmsClient(Mock()))
        with patch.object(AwsIamClient, "find_policy_arn", side_effect=[None, "", "some_policy_arn"]) as find_policy:
            self.assertFalse(client._delivery_role_policy_exists())
            self.assertFalse(client._delivery_role_policy_exists())
            self.assertTrue(client._delivery_role_policy_exists())
        find_policy.assert_called_with("vpc_flow_log_role_policy")


class TestAwsFlowLogCompliance(AwsScannerTestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClient(Mock(), AwsIamClient(Mock()), AwsLogsClient(Mock()), AwsKmsClient(Mock()))

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
        applied = [Mock(name=f"applied_action_{i}") for i in range(6)]
        actions = [
            self.mock_action(CreateVpcLogGroupAction, logs, applied[0]),
            self.mock_action(CreateFlowLogAction, ec2, applied[1]),
            self.mock_action(CreateFlowLogDeliveryRoleAction, iam, applied[2]),
            self.mock_action(DeleteFlowLogAction, ec2, applied[3]),
            self.mock_action(DeleteFlowLogDeliveryRoleAction, iam, applied[4]),
            self.mock_action(PutVpcLogGroupSubscriptionFilterAction, logs, applied[5]),
        ]
        self.assertEqual(applied, AwsVpcClient(ec2, iam, logs, kms).apply(actions))

    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClient(AwsEC2Client(Mock()), AwsIamClient(Mock()), AwsLogsClient(Mock()), AwsKmsClient(Mock()))

    def test_enforcement_actions(self) -> None:
        a_vpc, vpc_act_1, vpc_act_2 = vpc(), delete_flow_log_action("42"), create_flow_log_action("99")
        acts = [vpc_act_1, vpc_act_2]
        role_act_1 = create_flow_log_delivery_role_action()
        role_acts = [role_act_1]
        lg_act_1 = put_vpc_log_group_subscription_filter_action()
        lg_acts = [lg_act_1]
        with patch.object(AwsVpcClient, "_vpc_enforcement_actions", side_effect=lambda v: acts if v == a_vpc else None):
            with patch.object(AwsVpcClient, "_delivery_role_enforcement_actions", return_value=role_acts):
                with patch.object(AwsVpcClient, "_vpc_log_group_enforcement_actions", return_value=lg_acts):
                    self.assertEqual(
                        [lg_act_1, role_act_1, vpc_act_1, vpc_act_2], self.client().enforcement_actions([a_vpc])
                    )

    def test_vpc_has_no_flow_logs(self) -> None:
        with patch.object(AwsVpcClient, "_get_flow_log_delivery_role_arn", return_value="an_arn"):
            actions = self.client()._vpc_enforcement_actions(vpc(id="a-vpc", flow_logs=[]))
        self.assertEqual([create_flow_log_action("a-vpc")], actions)
        self.assertEqual("an_arn", next(iter(actions)).permission_resolver())

    def test_vpc_no_flow_log_action(self) -> None:
        self.assertEqual([], self.client()._vpc_enforcement_actions(vpc(flow_logs=[flow_log()])))

    def test_vpc_delete_redundant_centralised(self) -> None:
        self.assertEqual(
            [delete_flow_log_action("2"), delete_flow_log_action("3")],
            self.client()._vpc_enforcement_actions(vpc(flow_logs=[flow_log("1"), flow_log("2"), flow_log("3")])),
        )

    def test_vpc_delete_misconfigured_centralised(self) -> None:
        self.assertEqual(
            [delete_flow_log_action("1"), delete_flow_log_action("3")],
            self.client()._vpc_enforcement_actions(
                vpc(flow_logs=[flow_log("1", status="a"), flow_log("2"), flow_log("3")])
            ),
        )

    def test_vpc_create_centralised(self) -> None:
        self.assertEqual(
            [create_flow_log_action("vpc-1")],
            self.client()._vpc_enforcement_actions(vpc(id="vpc-1", flow_logs=[flow_log(log_group_name="a")])),
        )

    def test_vpc_delete_misconfigured_and_create_centralised(self) -> None:
        self.assertEqual(
            [delete_flow_log_action("1"), create_flow_log_action("vpc-a")],
            self.client()._vpc_enforcement_actions(vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])),
        )

    def test_no_delivery_role_action_when_role_is_compliant(self) -> None:
        compliant_role = role(name="compliant")
        with patch.object(AwsVpcClient, "_is_flow_log_role_compliant", side_effect=lambda r: r == compliant_role):
            with patch.object(AwsVpcClient, "_find_flow_log_delivery_role", return_value=compliant_role):
                self.assertEqual([], self.client()._delivery_role_enforcement_actions())

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

    def test_create_central_vpc_log_group_with_subscription_filter_when_missing(self) -> None:
        with patch.object(AwsVpcClient, "_find_log_group", return_value=None) as find_log_group:
            self.assertEqual(
                [create_vpc_log_group_action(), put_vpc_log_group_subscription_filter_action()],
                self.client()._vpc_log_group_enforcement_actions(),
            )
        find_log_group.assert_called_once_with("/vpc/flow_log")

    def test_put_subscription_filter_when_central_vpc_log_group_is_not_compliant(self) -> None:
        with patch.object(AwsVpcClient, "_find_log_group", return_value=log_group(subscription_filters=[])):
            self.assertEqual(
                [put_vpc_log_group_subscription_filter_action()],
                self.client()._vpc_log_group_enforcement_actions(),
            )

    def test_no_central_vpc_log_group_action_when_log_group_is_compliant(self) -> None:
        with patch.object(AwsVpcClient, "_find_log_group", return_value=log_group()):
            self.assertEqual([], self.client()._vpc_log_group_enforcement_actions())


class TestLogGroupCompliance(AwsScannerTestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClient(AwsEC2Client(Mock()), AwsIamClient(Mock()), AwsLogsClient(Mock()), AwsKmsClient(Mock()))

    def test_central_vpc_log_group(self) -> None:
        self.assertTrue(
            self.client()._is_central_vpc_log_group(
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
        self.assertFalse(self.client()._is_central_vpc_log_group(log_group(name="/vpc/something_else")))
        self.assertFalse(self.client()._is_central_vpc_log_group(log_group(subscription_filters=[])))
        self.assertFalse(
            self.client()._is_central_vpc_log_group(
                log_group(subscription_filters=[subscription_filter(filter_pattern="something")])
            )
        )
        self.assertFalse(
            self.client()._is_central_vpc_log_group(
                log_group(subscription_filters=[subscription_filter(destination_arn="somewhere")])
            )
        )
