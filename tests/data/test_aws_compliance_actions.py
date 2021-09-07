from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call, patch

from contextlib import redirect_stderr
from io import StringIO

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_scanner_exceptions import AwsScannerException

from tests import _raise
from tests.test_types_generator import (
    create_vpc_log_group_action,
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    delete_flow_log_action,
    delete_flow_log_delivery_role_action,
    put_vpc_log_group_subscription_filter_action,
    role,
)


class TestAwsComplianceActions(AwsScannerTestCase):
    def test_apply_success(self) -> None:
        client = Mock()
        action = type("TestAction", (ComplianceAction,), {"_apply": lambda s, c: self.assertEqual(c, client)})
        self.assertEqual("applied", action("something").apply(client).status)

    def test_apply_failure(self) -> None:
        client = Mock()
        action = type("TestAction", (ComplianceAction,), {"_apply": lambda s, c: _raise(AwsScannerException("boom"))})
        with redirect_stderr(StringIO()) as err:
            self.assertEqual("failed: boom", action("an_action").apply(client).status)
        self.assertIn("an_action failed: boom", err.getvalue())

    def test_delete_flow_log_action(self) -> None:
        with patch.object(AwsEC2Client, "delete_flow_logs") as delete_flow_logs:
            delete_flow_log_action(flow_log_id="42")._apply(AwsEC2Client(Mock()))
        delete_flow_logs.assert_called_once_with("42")

    def test_create_flow_log_action(self) -> None:
        with patch.object(AwsEC2Client, "create_flow_logs") as create_flow_logs:
            create_flow_log_action(vpc_id="8")._apply(AwsEC2Client(Mock()))
        create_flow_logs.assert_called_once_with("8", "/vpc/flow_log", "arn:aws:iam::112233445566:role/a_role")

    def test_create_flow_log_delivery_role_action(self) -> None:
        a_role = role(name="vpc_flow_log_role")
        pol = a_role.policies[0]
        with patch.object(
            AwsIamClient,
            "create_role",
            side_effect=lambda n, p: a_role if n == a_role.name and p == a_role.assume_policy else None,
        ):
            with patch.object(
                AwsIamClient,
                "create_policy",
                side_effect=lambda p, d: pol if p == pol.name and d == pol.document else None,
            ):
                with patch.object(AwsIamClient, "attach_role_policy") as attach_role_policy:
                    create_flow_log_delivery_role_action()._apply(AwsIamClient(Mock()))
        attach_role_policy.assert_called_once_with(a_role, pol)

    def test_delete_flow_log_delivery_role_action(self) -> None:
        client = Mock(spec=AwsIamClient)
        delete_flow_log_delivery_role_action()._apply(client)
        self.assertEqual(
            [call.delete_role("delete_me"), call.delete_policy("vpc_flow_log_role_policy")], client.mock_calls
        )

    def test_create_central_vpc_log_group_action(self) -> None:
        with patch.object(AwsLogsClient, "create_log_group") as create_log_group:
            create_vpc_log_group_action()._apply(AwsLogsClient(Mock()))
        create_log_group.assert_called_once_with("/vpc/flow_log")

    def test_put_central_vpc_log_group_subscription_filter_action(self) -> None:
        with patch.object(AwsLogsClient, "put_subscription_filter") as put_subscription_filter:
            put_vpc_log_group_subscription_filter_action()._apply(AwsLogsClient(Mock()))
        put_subscription_filter.assert_called_once_with(
            log_group_name="/vpc/flow_log",
            filter_name="/vpc/flow_log_sub_filter",
            filter_pattern="[version, account_id, interface_id]",
            destination_arn="arn:aws:logs:::destination:central",
        )
