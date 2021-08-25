from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.composite.aws_vpc_client import AwsVpcClient

from tests.test_types_generator import (
    create_flow_log_action,
    delete_flow_log_action,
    flow_log,
    log_group,
    policy,
    role,
    subscription_filter,
    vpc,
)


class TestAwsVpcClient(AwsScannerTestCase):
    def test_list_vpcs(self) -> None:
        log_role = role(name="a_log_role")
        vpcs = [vpc(flow_logs=[flow_log(deliver_log_role_arn=None)]), vpc()]
        client = AwsVpcClient(AwsEC2Client(Mock()), AwsIamClient(Mock()), AwsLogsClient(Mock()))
        with patch.object(AwsIamClient, "get_role_by_arn", side_effect=lambda a: log_role if a == "role_arn" else None):
            with patch.object(AwsEC2Client, "list_vpcs", return_value=vpcs):
                enriched = client.list_vpcs()
        self.assertEqual(vpcs, enriched)
        self.assertEqual([None, log_role], [fl.deliver_log_role for v in vpcs for fl in v.flow_logs])

    def test_find_flow_log_delivery_role(self) -> None:
        delivery_role = role(name="the_delivery_role")
        ec2, iam, logs = Mock(), Mock(), Mock()
        with patch.object(iam, "get_role", side_effect=lambda n: delivery_role if n == "vpc_flow_log_role" else None):
            self.assertEqual(delivery_role, AwsVpcClient(ec2, iam, logs).find_flow_log_delivery_role())

    def test_flow_log_role_compliant(self) -> None:
        delivery_role = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]})],
        )
        ec2, iam, logs = Mock(), Mock(), Mock()
        self.assertTrue(AwsVpcClient(ec2, iam, logs).is_flow_log_role_compliant(delivery_role))

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
        ec2, iam, logs = Mock(), Mock(), Mock()
        self.assertFalse(AwsVpcClient(ec2, iam, logs).is_flow_log_role_compliant(invalid_assume_policy))
        self.assertFalse(AwsVpcClient(ec2, iam, logs).is_flow_log_role_compliant(invalid_policy_document))
        self.assertFalse(AwsVpcClient(ec2, iam, logs).is_flow_log_role_compliant(missing_policy_document))


class TestAwsFlowLogCompliance(AwsScannerTestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClient(Mock(), AwsIamClient(Mock()), Mock())

    def test_flow_log_centralised(self) -> None:
        self.assertTrue(self.client().is_flow_log_centralised(flow_log(log_group_name="/vpc/flow_log")))

    def test_flow_log_not_centralised(self) -> None:
        self.assertFalse(self.client().is_flow_log_centralised(flow_log(log_group_name=None)))
        self.assertFalse(self.client().is_flow_log_centralised(flow_log(log_group_name="/vpc/something_else")))

    def test_flow_log_not_misconfigured(self) -> None:
        self.assertFalse(self.client().is_flow_log_misconfigured(flow_log()))
        self.assertFalse(self.client().is_flow_log_misconfigured(flow_log(log_group_name="/vpc/something_else")))

    def test_flow_log_misconfigured(self) -> None:
        self.assertTrue(self.client().is_flow_log_misconfigured(flow_log(status="a")))
        self.assertTrue(self.client().is_flow_log_misconfigured(flow_log(traffic_type="b")))
        self.assertTrue(self.client().is_flow_log_misconfigured(flow_log(log_format="c")))
        self.assertTrue(self.client().is_flow_log_misconfigured(flow_log(deliver_log_role=None)))
        self.assertTrue(self.client().is_flow_log_misconfigured(flow_log(deliver_log_role=role(assume_policy={}))))


class TestAwsVpcEnforcementActions(AwsScannerTestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClient(Mock(), Mock(), Mock())

    def test_vpc_is_empty(self) -> None:
        self.assertEqual(
            {create_flow_log_action("a-vpc")}, self.client().enforcement_actions(vpc(id="a-vpc", flow_logs=[]))
        )

    def test_vpc_no_flow_log_action(self) -> None:
        self.assertEqual(set(), self.client().enforcement_actions(vpc(flow_logs=[flow_log()])))

    def test_vpc_delete_redundant_centralised(self) -> None:
        self.assertEqual(
            {delete_flow_log_action("2"), delete_flow_log_action("3")},
            self.client().enforcement_actions(vpc(flow_logs=[flow_log("1"), flow_log("2"), flow_log("3")])),
        )

    def test_vpc_delete_misconfigured_centralised(self) -> None:
        self.assertEqual(
            {delete_flow_log_action("1"), delete_flow_log_action("3")},
            self.client().enforcement_actions(vpc(flow_logs=[flow_log("1", status="a"), flow_log("2"), flow_log("3")])),
        )

    def test_vpc_create_centralised(self) -> None:
        self.assertEqual(
            {create_flow_log_action("vpc-1")},
            self.client().enforcement_actions(vpc(id="vpc-1", flow_logs=[flow_log(log_group_name="a")])),
        )

    def test_vpc_delete_misconfigured_and_create_centralised(self) -> None:
        self.assertEqual(
            {create_flow_log_action("vpc-a"), delete_flow_log_action("1")},
            self.client().enforcement_actions(vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])),
        )


class TestLogsTypesCompliance(AwsScannerTestCase):
    @staticmethod
    def client() -> AwsVpcClient:
        return AwsVpcClient(Mock(), Mock(), Mock())

    def test_central_vpc_log_group(self) -> None:
        self.assertTrue(
            self.client().is_central_vpc_log_group(
                log_group(
                    name="/vpc/central_flow_log_5678",
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
        self.assertFalse(self.client().is_central_vpc_log_group(log_group(name="/vpc/something_else")))
        self.assertFalse(self.client().is_central_vpc_log_group(log_group(subscription_filters=[])))
        self.assertFalse(
            self.client().is_central_vpc_log_group(
                log_group(subscription_filters=[subscription_filter(filter_pattern="something")])
            )
        )
        self.assertFalse(
            self.client().is_central_vpc_log_group(
                log_group(subscription_filters=[subscription_filter(destination_arn="somewhere")])
            )
        )


class TestCentralVpcLogGroup(AwsScannerTestCase):
    def test_provide_central_vpc_log_group(self) -> None:
        log_groups = [log_group(name="/something_else"), log_group()]
        logs_client = Mock(describe_log_groups=Mock(return_value=log_groups))
        with patch.object(AwsVpcClient, "_create_central_vpc_log_group") as create:
            self.assertEqual(log_groups[1], AwsVpcClient(Mock(), Mock(), logs_client).provide_central_vpc_log_group())
        create.assert_not_called()

    def test_provide_central_vpc_log_group_creates_if_not_exists(self) -> None:
        lg = log_group(name="the-log-group")
        logs_client = Mock(describe_log_groups=Mock(return_value=[]))
        with patch.object(AwsVpcClient, "_create_central_vpc_log_group", return_value=lg) as create:
            self.assertEqual(lg, AwsVpcClient(Mock(), Mock(), logs_client).provide_central_vpc_log_group())
        create.assert_called_once()

    def test_create_central_vpc_log_group(self) -> None:
        create_log_group = Mock()
        put_subscription_filter = Mock()
        logs_client = Mock(create_log_group=create_log_group, put_subscription_filter=put_subscription_filter)
        client = AwsVpcClient(Mock(), Mock(), logs_client)
        clg = client._create_central_vpc_log_group()
        self.assertTrue(client.is_central_vpc_log_group(clg))
        self.assertRegex(clg.name, r"/vpc/central_flow_log_\d{4}")
        self.assertRegex(create_log_group.call_args[1]["name"], clg.name)
        sub_filter = put_subscription_filter.call_args[1]["subscription_filter"]
        self.assertEqual(clg.name, sub_filter.log_group_name)
        self.assertEqual(clg.subscription_filters[0], sub_filter)


class TestAwsEC2ClientApplyActions(AwsScannerTestCase):
    def test_apply_actions(self) -> None:
        client = AwsVpcClient(AwsEC2Client(Mock()), Mock(), Mock())
        c1, c2 = create_flow_log_action(vpc_id="vpc-1"), create_flow_log_action(vpc_id="vpc-2")
        d1, d2 = delete_flow_log_action(flow_log_id="fl-1"), delete_flow_log_action(flow_log_id="fl-2")
        with patch.object(AwsEC2Client, "create_flow_logs", side_effect=[True, False]) as mock_create:
            with patch.object(AwsEC2Client, "delete_flow_logs", side_effect=[False, True]) as mock_delete:
                self.assertEqual([c1, d1, c2, d2], client.apply([c1, d1, c2, d2]))
        mock_create.assert_has_calls([call("vpc-1"), call("vpc-2")])
        mock_delete.assert_has_calls([call("fl-1"), call("fl-2")])
        self.assertEqual(["applied", "failed"], [c1.status, c2.status])
        self.assertEqual(["failed", "applied"], [d1.status, d2.status])
