from tests.aws_scanner_test_case import AwsScannerTestCase

from src.data.aws_ec2_flow_log_actions import to_flow_log_actions

from tests.test_types_generator import create_flow_log_action, delete_flow_log_action, flow_log, vpc


class TestAwsEC2FlowLogActions(AwsScannerTestCase):
    def test_vpc_no_flow_log_action(self) -> None:
        self.assertEqual(set(), to_flow_log_actions(vpc(flow_logs=[flow_log()])))

    def test_vpc_delete_redundant_centralised(self) -> None:
        self.assertEqual(
            {delete_flow_log_action("2"), delete_flow_log_action("3")},
            to_flow_log_actions(vpc(flow_logs=[flow_log("1"), flow_log("2"), flow_log("3")])),
        )

    def test_vpc_delete_misconfigured_centralised(self) -> None:
        self.assertEqual(
            {delete_flow_log_action("1"), delete_flow_log_action("3")},
            to_flow_log_actions(vpc(flow_logs=[flow_log("1", status="a"), flow_log("2"), flow_log("3")])),
        )

    def test_vpc_create_centralised(self) -> None:
        self.assertEqual(
            {create_flow_log_action("vpc-1")},
            to_flow_log_actions(vpc(id="vpc-1", flow_logs=[flow_log(log_destination="a")])),
        )

    def test_vpc_delete_misconfigured_and_create_centralised(self) -> None:
        self.assertEqual(
            {create_flow_log_action("vpc-a"), delete_flow_log_action("1")},
            to_flow_log_actions(vpc(id="vpc-a", flow_logs=[flow_log(id="1", status="a")])),
        )
