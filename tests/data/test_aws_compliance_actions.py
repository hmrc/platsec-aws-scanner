from logging import ERROR
from typing import Any
from unittest.mock import Mock, call
from src import PLATSEC_SCANNER_TAGS
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.aws_scanner_config import AwsScannerConfig as Config
from src.aws_scanner_config import LogGroupConfig
from src.clients.aws_hosted_zones_client import AwsHostedZonesClient
from src.data.aws_compliance_actions import ComplianceAction
from src.data.aws_scanner_exceptions import AwsScannerException
from src.data.aws_common_types import ServiceName

from tests import _raise
from tests.clients.composite.test_aws_vpc_client import AwsVpcClientBuilder
from tests.test_types_generator import (
    compliance_action_report,
    policy,
    delete_flow_log_action,
    delete_query_log_action,
    role,
    create_flow_log_action,
    create_flow_log_delivery_role_action,
    delete_flow_log_delivery_role_action,
    delete_vpc_log_group_subscription_filter_action,
    create_log_group_action,
    password_policy,
    put_vpc_log_group_subscription_filter_action,
    put_log_group_retention_policy_action,
    tag_flow_log_delivery_role_action,
    tag_log_group_action,
    tag,
    update_password_policy_action,
    create_query_log_action,
    resource_policy_document,
    put_route53_log_group_resource_policy_action,
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


def test_apply_delete_query_log_action() -> None:
    logsClient = Mock(spec=AwsHostedZonesClient)
    delete_query_log_action(route53_client=logsClient, hosted_zone_id="42")._apply()
    logsClient.delete_query_logging_config.assert_called_once_with("42")


def test_plan_delete_flow_log_action() -> None:
    expected = compliance_action_report(description="Delete VPC flow log", details={"flow_log_id": "fl-1234"})
    assert expected == delete_flow_log_action().plan()


def test_plan_delete_query_log_action() -> None:
    expected = compliance_action_report(
        description="Delete Route53 query logging config", details={"hosted_zone_id": "hosted_zone_id"}
    )
    assert expected == delete_query_log_action().plan()


def test_apply_create_flow_log_action() -> None:
    builder = AwsVpcClientBuilder()
    builder.with_create_flow_logs()
    builder.with_roles([role()])
    client = builder.build()
    create_flow_log_action(ec2_client=client.ec2, iam=client.iam, vpc_id="8")._apply()
    builder.ec2.create_flow_logs.assert_called_once_with("8", "/vpc/flow_log", "arn:aws:iam::112233445566:role/a_role")


def test_apply_create_query_log_action() -> None:
    route53_client = Mock(spec=AwsHostedZonesClient)
    route53_client.create_query_logging_config = Mock()
    iam: AwsIamClient = Mock(spec=AwsIamClient)
    zone_id: str = "zoneId"
    create_query_log_action(route53_client=route53_client, iam=iam, log_group_config=Config().logs_route53_query_log_group_config(), zone_id=zone_id)._apply()
    route53_client.create_query_logging_config.assert_called_once_with(
        "zoneId", f"arn:aws:logs:us-east-1:account_id:log-group:{Config().logs_route53_query_log_group_config().logs_group_name}"
    )


def test_apply_put_resource_policy_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    put_route53_log_group_resource_policy_action(log_group_config=Config().logs_route53_query_log_group_config(), logs=logs)._apply()
    logs.put_resource_policy.assert_called_once_with(
        policy_name="route53_query_logs_to_cloudwatch_logs",
        policy_document=resource_policy_document(),
    )


def test_plan_create_flow_log_action() -> None:
    expected = compliance_action_report(
        description="Create VPC flow log", details={"vpc_id": "vpc-1234", "log_group_name": "/vpc/flow_log"}
    )
    assert expected == create_flow_log_action().plan()


def test_plan_create_query_log_action() -> None:
    
    expected = compliance_action_report(
        description="Create log group",
        details={"zone_id": "zoneId", "log_group_name": Config().logs_route53_query_log_group_config().logs_group_name},
    )
   
    assert expected == create_query_log_action(log_group_config=Config().logs_route53_query_log_group_config()).plan()


def test_plan_put_resource_policy_action() -> None:
    expected = compliance_action_report(
        description="Put route53 log group resource policy",
        details={"policy_name": "route53_query_logs_to_cloudwatch_logs"},
    )
    assert expected == put_route53_log_group_resource_policy_action(log_group_config= Config().logs_route53_query_log_group_config()).plan()


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
    log_group_config = Config().logs_vpc_flow_log_group_config()
    log_group_config.logs_group_name = "/vpc/flow_log"
    create_log_group_action(log_group_config=log_group_config, logs=logs)._apply()
    logs.create_log_group.assert_called_once_with("/vpc/flow_log")


def test_plan_create_central_vpc_log_group_action() -> None:
    expected = compliance_action_report(description="Create log group", details=dict(log_group_name="/vpc/flow_log"))
    log_group_config = Config().logs_vpc_flow_log_group_config()
    log_group_config.logs_group_name = "/vpc/flow_log"
    assert expected == create_log_group_action(log_group_config = log_group_config).plan()


def test_plan_create_route53_log_group_action() -> None:
    expected = compliance_action_report(
        description="Create log group", details=dict(log_group_name="logs_route53_log_group_name")
    )
    log_group_config = Config().logs_route53_query_log_group_config()
    log_group_config.logs_group_name = "logs_route53_log_group_name"
    assert expected == create_log_group_action(log_group_config=log_group_config).plan()


def test_apply_create_route53_log_group_action() -> None:
    logs = Mock()
    log_group_config = Config().logs_route53_query_log_group_config()
    log_group_config.logs_group_name = "logs_route53_log_group_name"
    create_log_group_action(logs=logs, log_group_config=log_group_config).apply()
    logs.create_log_group.assert_called_once_with("logs_route53_log_group_name")


def test_apply_put_central_vpc_log_group_subscription_filter_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    
    log_group_config=Config().logs_vpc_flow_log_group_config()
    put_vpc_log_group_subscription_filter_action(log_group_config=log_group_config, logs=logs)._apply()
    logs.put_subscription_filter.assert_called_once_with(
        log_group_name="/vpc/flow_log",
        filter_name="/vpc/flow_log_sub_filter",
        filter_pattern="[version, account_id, interface_id]",
        destination_arn="arn:aws:logs:::destination:central",
    )


def test_plan_put_central_vpc_log_group_subscription_filter_action() -> None:
    log_group_config=Config().logs_vpc_flow_log_group_config()
    expected = compliance_action_report(
        description=f"Put central /vpc/flow_log log group subscription filter",
        details=dict(log_group_name="/vpc/flow_log", destination_arn="arn:aws:logs:::destination:central"),
    )
    assert (
        expected
        == put_vpc_log_group_subscription_filter_action(log_group_config= log_group_config).plan()
    )


def test_apply_delete_vpc_log_group_subscription_filter_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    config = Mock()
    config.logs_group_name = Mock(return_value="/vpc/flow_log")
    config.logs_log_group_subscription_filter_name = Mock(return_value="/vpc/flow_log_sub_filter")
    delete_vpc_log_group_subscription_filter_action(
        Config().logs_vpc_flow_log_group_config(),
        logs=logs,
    )._apply()
    logs.delete_subscription_filter.assert_called_once_with(
        log_group_name="/vpc/flow_log", filter_name="/vpc/flow_log_sub_filter"
    )


def test_plan_delete_vpc_log_group_subscription_filter_action() -> None:
    expected = compliance_action_report(
        description=f"Delete central /vpc/flow_log_sub_filter log group subscription filter",
        details=dict(log_group_name="/vpc/flow_log", subscription_filter_name="/vpc/flow_log_sub_filter"),
    )
    assert (
        expected
        == delete_vpc_log_group_subscription_filter_action(
            Config().logs_vpc_flow_log_group_config()
        ).plan()
    )


def test_plan_put_vpc_log_group_retention_policy_action() -> None:
    log_group_config =  Config().logs_vpc_flow_log_group_config()
    
    assert (
        compliance_action_report(
            description=f"Put {log_group_config.logs_group_name} log group retention policy",
            details={"log_group_name": log_group_config.logs_group_name, "retention_days": 14},
        )
        == put_log_group_retention_policy_action(
           log_group_config=log_group_config
        ).plan()
    )


def test_plan_put_route53_log_group_retention_policy_action() -> None:
    log_group_config= Config().logs_route53_query_log_group_config()
    log_group_config.logs_group_retention_policy_days = 5
    assert (
        compliance_action_report(
            description=f"Put {log_group_config.logs_group_name} log group retention policy",
            details={"log_group_name": log_group_config.logs_group_name, "retention_days": 5},
        )
        == put_log_group_retention_policy_action(
           log_group_config
        ).plan()
    )


def test_apply_put_route53_log_group_retention_policy_action() -> None:
    logs = Mock()
    log_group_config= Config().logs_route53_query_log_group_config()
    log_group_config.logs_group_retention_policy_days = 5
    put_log_group_retention_policy_action(
        log_group_config=log_group_config,
        logs=logs,
    ).apply()
    logs.put_retention_policy.assert_called_once_with(log_group_name= log_group_config.logs_group_name, retention_days=5)


def test_apply_put_vpc_log_group_retention_policy_action() -> None:
    logs = Mock(spec=AwsLogsClient)
    log_group_config= Config().logs_vpc_flow_log_group_config()
    log_group_config.logs_group_retention_policy_days = 14
    put_log_group_retention_policy_action(
        log_group_config=log_group_config,
        logs=logs,
    ).apply()
    logs.put_retention_policy.assert_called_once_with(log_group_name=log_group_config.logs_group_name, retention_days=14)


def test_apply_tag_route53_log_group_action() -> None:
    logs = Mock()
    log_group_config= Config().logs_route53_query_log_group_config()
    tag_log_group_action(
        log_group_config,
        logs=logs,
    ).apply()
    logs.tag_log_group.assert_called_once_with(log_group_name= log_group_config.logs_group_name, tags=PLATSEC_SCANNER_TAGS)


def test_plan_tag_route53_log_group_action() -> None:
    log_group_config= Config().logs_route53_query_log_group_config()
    assert (
        compliance_action_report(
            description="Tag central log group",
            details={"log_group_name": log_group_config.logs_group_name , "tags": PLATSEC_SCANNER_TAGS},
        )
        == tag_log_group_action(
            log_group_config
        ).plan()
    )


def test_plan_tag_vpc_log_group_action() -> None:
    log_group_config= Config().logs_vpc_flow_log_group_config()
    assert (
        compliance_action_report(
            description="Tag central log group",
            details={
                "log_group_name": "/vpc/flow_log",
                "tags": [
                    tag("allow-management-by-platsec-scanner", "true"),
                    tag("source-code", "https://github.com/hmrc/platsec-aws-scanner"),
                    tag("business-unit", "MDTP"),
                    tag("owner", "PlatSec"),
                ],
            },
        )
        == tag_log_group_action(
            log_group_config= Config().logs_vpc_flow_log_group_config()
        ).plan()
    )


def test_apply_tag_vpc_log_group_action() -> None:
    log_group_config= Config().logs_vpc_flow_log_group_config()
    logs = Mock(spec=AwsLogsClient)
    tag_log_group_action(
       log_group_config,
        logs=logs,
    )._apply()
    logs.tag_log_group.assert_called_once_with(
        log_group_name="/vpc/flow_log",
        tags=[
            tag("allow-management-by-platsec-scanner", "true"),
            tag("source-code", "https://github.com/hmrc/platsec-aws-scanner"),
            tag("business-unit", "MDTP"),
            tag("owner", "PlatSec"),
        ],
    )


def test_plan_tag_flow_log_delivery_role_action() -> None:
    assert (
        compliance_action_report(
            description="Tag delivery role for VPC flow log",
            details={
                "role_name": "vpc_flow_log_role",
                "tags": [
                    tag("allow-management-by-platsec-scanner", "true"),
                    tag("source-code", "https://github.com/hmrc/platsec-aws-scanner"),
                    tag("business-unit", "MDTP"),
                    tag("owner", "PlatSec"),
                ],
            },
        )
        == tag_flow_log_delivery_role_action().plan()
    )


def test_apply_tag_flow_log_delivery_role_action() -> None:
    iam = Mock(spec=AwsIamClient)
    tag_flow_log_delivery_role_action(iam=iam)._apply()
    iam.tag_role.assert_called_once_with(
        name="vpc_flow_log_role",
        tags=[
            tag("allow-management-by-platsec-scanner", "true"),
            tag("source-code", "https://github.com/hmrc/platsec-aws-scanner"),
            tag("business-unit", "MDTP"),
            tag("owner", "PlatSec"),
        ],
    )


def test_plan_update_password_policy_action() -> None:
    assert update_password_policy_action().plan() == compliance_action_report(
        description="Update IAM password policy",
        details={"password_policy": password_policy()},
    )


def test_apply_update_password_policy_action() -> None:
    iam = Mock(spec=AwsIamClient)
    update_password_policy_action(iam=iam)._apply()
    iam.update_account_password_policy.assert_called_once_with(password_policy())
