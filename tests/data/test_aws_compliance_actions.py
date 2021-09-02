from typing import Any

from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_scanner_exceptions import AwsScannerException

from tests import _raise
from tests.test_types_generator import (
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    delete_flow_log_action,
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
        self.assertEqual("failed: boom", action("something").apply(client).status)

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


class SuccessAction(ComplianceAction):
    def _apply(self, client: Any) -> None:
        pass


class FailureAction(ComplianceAction):
    def _apply(self, client: Any) -> None:
        pass
