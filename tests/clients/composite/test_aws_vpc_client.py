from typing import Type

from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_compliance_actions import ComplianceAction

from tests.test_types_generator import (
    create_flow_log_action,
    delete_flow_log_action,
    flow_log,
    vpc,
)


def client() -> AwsVpcClient:
    return AwsVpcClient(AwsEC2Client(Mock()))


class TestAwsVpcClient(TestCase):
    def test_list_vpcs(self) -> None:
        expected_vpcs = [vpc(id="1"), vpc(id="2")]
        vpc_client = AwsVpcClient(ec2=Mock(list_vpcs=Mock(return_value=expected_vpcs)))
        self.assertEqual(expected_vpcs, vpc_client.list_vpcs())


class TestAwsFlowLogCompliance(TestCase):
    def test_flow_log_centralised(self) -> None:
        self.assertTrue(client()._is_flow_log_centralised(flow_log(log_destination="central_log_bucket")))

    def test_flow_log_not_centralised(self) -> None:
        self.assertFalse(client()._is_flow_log_centralised(flow_log(log_destination=None)))
        self.assertFalse(client()._is_flow_log_centralised(flow_log(log_destination="other_bucket_arn")))

    def test_flow_log_not_misconfigured(self) -> None:
        self.assertFalse(client()._is_flow_log_misconfigured(flow_log()))
        self.assertFalse(client()._is_flow_log_misconfigured(flow_log(log_destination_type="s3")))

    def test_flow_log_misconfigured(self) -> None:
        self.assertTrue(client()._is_flow_log_misconfigured(flow_log(status="a")))
        self.assertTrue(client()._is_flow_log_misconfigured(flow_log(traffic_type="b")))
        self.assertTrue(client()._is_flow_log_misconfigured(flow_log(log_format="c")))
        self.assertTrue(client()._is_flow_log_misconfigured(flow_log(log_destination_type="s4")))


class TestAwsEnforcementActions(TestCase):
    @staticmethod
    def mock_action(action: Type[ComplianceAction], expected_client: Mock, applied_action: Mock) -> Mock:
        return Mock(spec=action, apply=Mock(side_effect=lambda c: applied_action if c == expected_client else None))

    def test_do_nothing_when_all_correct(self) -> None:
        self.assertEqual([], client().enforcement_actions([vpc()]))

    def test_create_vpc_flow_logs(self) -> None:
        self.assertEqual(
            [create_flow_log_action(vpc_id="vpc-1234")],
            client().enforcement_actions([vpc(flow_logs=[])]),
        )

    def test_vpc_delete_redundant_centralised(self) -> None:
        self.assertEqual(
            [delete_flow_log_action(flow_log_id="2"), delete_flow_log_action(flow_log_id="3")],
            client().enforcement_actions(
                [
                    vpc(
                        flow_logs=[
                            flow_log("1"),  # the one we want to keep
                            flow_log("2"),  # duplicate
                            flow_log("3"),  # duplicate
                            flow_log(id="unrelated_flow_log", log_destination="unrelated flow log"),
                        ]
                    )
                ],
            ),
        )

    def test_vpc_delete_misconfigured_centralised(self) -> None:
        self.assertEqual(
            [delete_flow_log_action(flow_log_id="1"), delete_flow_log_action(flow_log_id="3")],
            client().enforcement_actions(
                [vpc(flow_logs=[flow_log("1", status="a"), flow_log("2"), flow_log("3")])],
            ),
        )

    def test_vpc_create_centralised(self) -> None:
        self.assertEqual(
            [create_flow_log_action(vpc_id="vpc-1")],
            client().enforcement_actions(
                [vpc(id="vpc-1", flow_logs=[flow_log(log_destination="a")])],
            ),
        )

    def test_vpc_delete_misconfigured_and_create_centralised(self) -> None:
        self.assertEqual(
            [delete_flow_log_action(flow_log_id="1"), create_flow_log_action(vpc_id="vpc-a")],
            client().enforcement_actions(
                [vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])],
            ),
        )
