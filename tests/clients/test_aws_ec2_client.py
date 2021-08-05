from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch

from contextlib import redirect_stderr
from io import StringIO
from typing import Any, Dict

from src.clients.aws_ec2_client import AwsEC2Client
from src.data.aws_ec2_types import Vpc
from src.data.aws_scanner_exceptions import UnsupportedActionException

from tests import _raise
from tests.clients import test_aws_ec2_client_responses as responses
from tests.test_types_generator import client_error, create_flow_log_action, delete_flow_log_action, flow_log, vpc


class TestAwsEC2ListVpcs(AwsScannerTestCase):
    def test_list_vpcs(self) -> None:
        ec2 = AwsEC2Client(Mock())
        with patch.object(ec2, "_describe_flow_logs", side_effect=lambda v: [flow_log()] if v.id == vpc().id else None):
            with patch.object(ec2, "_describe_vpcs", return_value=[vpc()]):
                self.assertEqual([vpc(flow_logs=[flow_log()])], ec2.list_vpcs())


class TestAwsEC2ClientDescribeVpcs(AwsScannerTestCase):
    def test_describe_vpcs_empty(self) -> None:
        ec2_client = AwsEC2Client(Mock(describe_vpcs=Mock(return_value={"Vpcs": []})))
        self.assertEqual([], ec2_client._describe_vpcs())

    def test_describe_vpcs(self) -> None:
        vpcs = [{"VpcId": "vpc-12312e654bf654d12"}, {"VpcId": "vpc-984a4654b65465e12"}]
        ec2_client = AwsEC2Client(Mock(describe_vpcs=Mock(return_value={"Vpcs": vpcs})))
        self.assertEqual([Vpc("vpc-12312e654bf654d12"), Vpc("vpc-984a4654b65465e12")], ec2_client._describe_vpcs())

    def test_describe_vpcs_failure(self) -> None:
        error = client_error("DescribeVpcs", "AccessDenied", "Access Denied")
        ec2_client = AwsEC2Client(Mock(describe_vpcs=Mock(side_effect=error)))
        with redirect_stderr(StringIO()) as err:
            self.assertEqual([], ec2_client._describe_vpcs())
        self.assertIn("AccessDenied", err.getvalue())


class TestAwsEC2ClientDescribeFlowLogs(AwsScannerTestCase):
    def describe_flow_logs(self, **kwargs) -> Dict[Any, Any]:
        self.assertEqual("resource-id", kwargs.get("Filters")[0].get("Name"))
        return {
            "vpc-no-flow-logs": lambda: responses.EMPTY_FLOW_LOGS,
            "vpc-with-flow-logs": lambda: responses.FLOW_LOGS,
            "vpc-error": lambda: _raise(client_error("DescribeFlowLogs", "AccessDenied", "Access Denied")),
        }[kwargs.get("Filters")[0].get("Values")[0]]()

    def ec2_client(self) -> AwsEC2Client:
        return AwsEC2Client(Mock(describe_flow_logs=Mock(side_effect=self.describe_flow_logs)))

    def test_describe_flow_logs_empty(self) -> None:
        self.assertEqual([], self.ec2_client()._describe_flow_logs(Vpc("vpc-no-flow-logs")))

    def test_describe_flow_logs(self) -> None:
        self.assertEqual(responses.EXPECTED_FLOW_LOGS, self.ec2_client()._describe_flow_logs(Vpc("vpc-with-flow-logs")))

    def test_describe_flow_logs_failure(self) -> None:
        with redirect_stderr(StringIO()) as err:
            self.assertEqual([], self.ec2_client()._describe_flow_logs(Vpc("vpc-error")))
        self.assertIn("AccessDenied", err.getvalue())
        self.assertIn("vpc-error", err.getvalue())


class TestAwsEC2ClientCreateFlowLog(AwsScannerTestCase):
    def test_create_flow_log_not_implemented(self) -> None:
        with self.assertRaises(UnsupportedActionException):
            AwsEC2Client(Mock())._create_flow_log("vpc-1")


class TestAwsEC2ClientDeleteFlowLog(AwsScannerTestCase):
    @staticmethod
    def delete_flow_logs(**kwargs) -> Dict[Any, Any]:
        return {
            "good-fl": lambda: responses.DELETE_FLOW_LOGS_SUCCESS,
            "fl-not-found": lambda: responses.DELETE_FLOW_LOGS_FAILURE,
            "bad-fl": lambda: _raise(client_error("DeleteFlowLogs", "AccessDenied", "Access Denied")),
        }[kwargs.get("FlowLogIds")[0]]()

    def ec2_client(self) -> AwsEC2Client:
        return AwsEC2Client(Mock(delete_flow_logs=Mock(side_effect=self.delete_flow_logs)))

    def test_delete_flow_log(self) -> None:
        self.assertTrue(self.ec2_client()._delete_flow_log(flow_log_id="good-fl"))

    def test_delete_flow_log_not_found(self) -> None:
        with redirect_stderr(StringIO()) as err:
            self.assertFalse(self.ec2_client()._delete_flow_log(flow_log_id="fl-not-found"))
        self.assertIn("InvalidFlowLogId.NotFound", err.getvalue())
        self.assertIn("bad-fl", err.getvalue())

    def test_delete_flow_log_failure(self) -> None:
        with redirect_stderr(StringIO()) as err:
            self.assertFalse(self.ec2_client()._delete_flow_log(flow_log_id="bad-fl"))
        self.assertIn("AccessDenied", err.getvalue())
        self.assertIn("bad-fl", err.getvalue())


class TestAwsEC2ClientApplyActions(AwsScannerTestCase):
    def test_apply_actions(self) -> None:
        c1, c2 = create_flow_log_action(vpc_id="vpc-1"), create_flow_log_action(vpc_id="vpc-2")
        d1, d2 = delete_flow_log_action(flow_log_id="fl-1"), delete_flow_log_action(flow_log_id="fl-2")
        with patch.object(AwsEC2Client, "_create_flow_log", side_effect=[True, False]) as mock_create:
            with patch.object(AwsEC2Client, "_delete_flow_log", side_effect=[False, True]) as mock_delete:
                self.assertEqual([c1, d1, c2, d2], AwsEC2Client(Mock()).apply([c1, d1, c2, d2]))
        mock_create.assert_has_calls([call("vpc-1"), call("vpc-2")])
        mock_delete.assert_has_calls([call("fl-1"), call("fl-2")])
        self.assertEqual(["applied", "failed"], [c1.status, c2.status])
        self.assertEqual(["failed", "applied"], [d1.status, d2.status])
