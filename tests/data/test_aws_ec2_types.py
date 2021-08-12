from tests.aws_scanner_test_case import AwsScannerTestCase

from tests.test_types_generator import flow_log


class TestAwsEC2TypesFlowLog(AwsScannerTestCase):
    def test_flow_log_centralised(self) -> None:
        self.assertTrue(flow_log(log_group_name="/vpc/flow_log").compliance.centralised)

    def test_flow_log_not_centralised(self) -> None:
        self.assertFalse(flow_log(log_group_name=None).compliance.centralised)
        self.assertFalse(flow_log(log_group_name="/vpc/something_else").compliance.centralised)

    def test_flow_log_not_misconfigured(self) -> None:
        self.assertFalse(flow_log().compliance.misconfigured)
        self.assertFalse(flow_log(log_group_name="/vpc/something_else").compliance.misconfigured)

    def test_flow_log_misconfigured(self) -> None:
        self.assertTrue(flow_log(status="a").compliance.misconfigured)
        self.assertTrue(flow_log(traffic_type="b").compliance.misconfigured)
        self.assertTrue(flow_log(log_format="c").compliance.misconfigured)