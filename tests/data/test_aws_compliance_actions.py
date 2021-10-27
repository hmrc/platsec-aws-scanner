from logging import ERROR
from typing import Any
from unittest.mock import Mock, call, patch

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_scanner_exceptions import AwsScannerException

from tests import _raise
from tests.clients.test_aws_vpc_client import AwsVpcClientBuilder
from tests.test_types_generator import (
    compliance_action_report,
    policy,
    update_log_group_kms_key_action,
    delete_flow_log_action,
    role,
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    delete_flow_log_delivery_role_action,
    create_vpc_log_group_action,
    delete_log_group_kms_key_alias_action,
    create_log_group_kms_key_action,
    put_vpc_log_group_subscription_filter_action,
    put_vpc_log_group_retention_policy_action,
    key,
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


def test_apply_create_flow_log_delivery_role_action() -> None:
    a_role = role(name="vpc_flow_log_role", policies=[policy(name="delivery_role_policy")])
    client = AwsVpcClientBuilder()
    client.with_create_role(a_role)
    client.with_policies(a_role.policies)
    client.with_attach_role_policy(a_role)

    create_flow_log_delivery_role_action(iam=client.build().iam)._apply()
    client.iam.attach_role_policy.assert_called_once_with(a_role, a_role.policies[0].arn)


def test_plan_create_flow_log_delivery_role_action() -> None:
    expected = compliance_action_report(
        description="Create delivery role for VPC flow log", details={"role_name": "vpc_flow_log_role"}
    )
    assert expected == create_flow_log_delivery_role_action().plan()


def test_apply_delete_flow_log_delivery_role_action() -> None:
    client = Mock(spec=AwsIamClient)
    delete_flow_log_delivery_role_action(iam=client)._apply()
    assert [call.delete_role("vpc_flow_log_role")] == client.mock_calls


def test_plan_delete_flow_log_delivery_role_action() -> None:
    expected = compliance_action_report(description="Delete delivery role for VPC flow log")
    assert expected == delete_flow_log_delivery_role_action().plan()


def test_apply_create_central_vpc_log_group_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    create_vpc_log_group_action(logs=logs)._apply()
    logs.create_log_group.assert_called_once_with("/vpc/flow_log")


def test_plan_create_central_vpc_log_group_action() -> None:
    expected = compliance_action_report(
        description="Create central VPC log group", details=dict(log_group_name="/vpc/flow_log")
    )
    assert expected == create_vpc_log_group_action().plan()


def test_apply_delete_log_group_kms_key_alias_action() -> None:
    kms = Mock(spec=AwsKmsClient)
    delete_log_group_kms_key_alias_action(kms=kms)._apply()
    kms.delete_alias.assert_called_once_with(name="an_alias")


def test_plan_delete_log_group_kms_key_alias_action() -> None:
    expected = compliance_action_report(description="Delete log group kms key alias")
    assert expected == delete_log_group_kms_key_alias_action().plan()


def test_apply_create_log_group_kms_key_action() -> None:
    a_key = key()
    with patch.object(AwsKmsClient, "create_key", return_value=a_key) as create_key:
        with patch.object(AwsKmsClient, "put_key_policy_statements") as put_key_policy_statements:
            expected_policy = [
                {"account": a_key.account_id},
                {"account": a_key.account_id, "region": a_key.region, "log_group_name": "/vpc/flow_log"},
            ]
            kms = AwsKmsClient(Mock())
            action = create_log_group_kms_key_action(kms=kms)
            assert {"key_id": "1234abcd"} == action._apply()

            create_key.assert_called_once_with(
                alias="an_alias",
                description="Autogenerated key for an_alias do not modify",
            )
            put_key_policy_statements.assert_called_once_with(key_id=a_key.id, statements=expected_policy)


def test_plan_create_log_group_kms_key_action() -> None:
    expected = compliance_action_report(description="Create log group kms key")
    assert expected == create_log_group_kms_key_action(kms=Mock()).plan()


def test_apply_put_central_vpc_log_group_subscription_filter_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    put_vpc_log_group_subscription_filter_action(logs=logs)._apply()
    logs.put_subscription_filter.assert_called_once_with(
        log_group_name="/vpc/flow_log",
        filter_name="/vpc/flow_log_sub_filter",
        filter_pattern="[version, account_id, interface_id]",
        destination_arn="arn:aws:logs:::destination:central",
    )


def test_plan_put_central_vpc_log_group_subscription_filter_action() -> None:
    expected = compliance_action_report(description="Put central VPC log group subscription filter")
    assert expected == put_vpc_log_group_subscription_filter_action().plan()


def test_apply_update_log_group_kms_key() -> None:
    expected_key_arn = key().arn
    builder = AwsVpcClientBuilder()
    builder.with_default_key()
    builder.with_default_alias()
    client = builder.build()
    update_log_group_kms_key_action(logs=client.logs, kms=client.kms)._apply()

    builder.logs.associate_kms_key.assert_called_once_with(log_group_name="/vpc/flow_log", kms_key_arn=expected_key_arn)


def test_plan_update_log_group_kms_key() -> None:
    assert compliance_action_report(description="Update log group kms key") == update_log_group_kms_key_action().plan()


def test_plan_put_vpc_log_group_retention_policy_action() -> None:
    assert (
        compliance_action_report(
            description="Put central VPC log group retention policy",
            details={"log_group_name": "/vpc/flow_log", "retention_days": 14},
        )
        == put_vpc_log_group_retention_policy_action().plan()
    )


def test_apply_put_vpc_log_group_retention_policy_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    put_vpc_log_group_retention_policy_action(logs=logs)._apply()
    logs.put_retention_policy.assert_called_once_with(log_group_name="/vpc/flow_log", retention_days=14)
