from logging import ERROR
from typing import Any
from unittest.mock import Mock

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_scanner_exceptions import AwsScannerException

from tests import _raise
from tests.clients.composite.test_aws_vpc_client import AwsVpcClientBuilder
from tests.test_types_generator import (
    compliance_action_report,
    delete_flow_log_action,
    role,
    create_flow_log_action,
    password_policy,
    update_password_policy_action,
)


def test_apply_success() -> None:
    action = type(
        "TestAction",
        (ComplianceAction,),
        {
            "_apply": lambda s: None,
            "plan": lambda s: compliance_action_report(),
        },
    )
    assert compliance_action_report(status="applied") == action("something").apply()


def test_apply_success_with_report() -> None:
    action = type(
        "TestAction",
        (ComplianceAction,),
        {
            "_apply": lambda s: dict(some_key=2),
            "plan": lambda s: compliance_action_report(description="bla", details=dict(a_key=1)),
        },
    )
    expected = compliance_action_report(status="applied", description="bla", details={"a_key": 1, "some_key": 2})
    assert expected == action("something").apply()


def test_apply_failure(caplog: Any) -> None:
    action = type(
        "TestAction",
        (ComplianceAction,),
        {
            "_apply": lambda s: _raise(AwsScannerException("boom")),
            "plan": lambda s: compliance_action_report(),
        },
    )
    with caplog.at_level(ERROR):
        assert compliance_action_report(status="failed: boom") == action("an_action").apply()
        assert "an_action failed: boom" in caplog.text


def test_apply_delete_flow_log_action() -> None:
    ec2 = Mock(spec=AwsEC2Client)
    delete_flow_log_action(ec2_client=ec2, flow_log_id="42")._apply()
    ec2.delete_flow_logs.assert_called_once_with("42")


def test_plan_delete_flow_log_action() -> None:
    expected = compliance_action_report(description="Delete VPC flow log", details={"flow_log_id": "fl-1234"})
    assert expected == delete_flow_log_action().plan()


def test_apply_create_flow_log_action() -> None:
    builder = AwsVpcClientBuilder()
    builder.with_create_flow_logs()
    builder.with_roles([role()])
    client = builder.build()
    create_flow_log_action(ec2_client=client.ec2, iam=client.iam, vpc_id="8")._apply()
    builder.ec2.create_flow_logs.assert_called_once_with("8", "/vpc/flow_log", "arn:aws:iam::112233445566:role/a_role")


def test_plan_create_flow_log_action() -> None:
    expected = compliance_action_report(
        description="Create VPC flow log", details={"vpc_id": "vpc-1234", "log_group_name": "/vpc/flow_log"}
    )
    assert expected == create_flow_log_action().plan()


def test_plan_update_password_policy_action() -> None:
    assert update_password_policy_action().plan() == compliance_action_report(
        description="Update IAM password policy",
        details={"password_policy": password_policy()},
    )


def test_apply_update_password_policy_action() -> None:
    iam = Mock(spec=AwsIamClient)
    update_password_policy_action(iam=iam)._apply()
    iam.update_account_password_policy.assert_called_once_with(password_policy())
