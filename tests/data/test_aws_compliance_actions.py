from unittest.mock import Mock, call, patch

from unittest import TestCase
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import ComplianceAction, ComplianceActionReport
from src.data.aws_scanner_exceptions import AwsScannerException

from tests import _raise, test_types_generator
from tests import test_types_generator as generator
from tests.clients.test_aws_vpc_client import AwsVpcClientBuilder
from tests.test_types_generator import policy, update_log_group_kms_key_action


class TestAwsComplianceActions(TestCase):
    def test_apply_success(self) -> None:
        action = type(
            "TestAction",
            (ComplianceAction,),
            {
                "_apply": lambda s: None,
                "plan": lambda s: ComplianceActionReport(),
            },
        )
        self.assertEqual("applied", action("something").apply().status)

    def test_apply_failure(self) -> None:
        action = type(
            "TestAction",
            (ComplianceAction,),
            {
                "_apply": lambda s: _raise(AwsScannerException("boom")),
                "plan": lambda s: ComplianceActionReport(),
            },
        )
        self.assertEqual("failed: boom", action("an_action").apply().status)
        # with redirect_stderr(StringIO()) as err: # todo fix
        # self.assertIn("an_action failed: boom", err.getvalue())

    def test_apply_delete_flow_log_action(self) -> None:
        ec2 = Mock(spec=AwsEC2Client)
        generator.delete_flow_log_action(ec2_client=ec2, flow_log_id="42")._apply()
        ec2.delete_flow_logs.assert_called_once_with("42")

    def test_plan_delete_flow_log_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Delete VPC flow log", details={"flow_log_id": "fl-1234"}),
            generator.delete_flow_log_action().plan(),
        )

    def test_apply_create_flow_log_action(self) -> None:
        builder = AwsVpcClientBuilder()
        builder.with_create_flow_logs()
        builder.with_roles([generator.role()])
        client = builder.build()
        generator.create_flow_log_action(ec2_client=client.ec2, iam=client.iam, vpc_id="8")._apply()

        builder.ec2.create_flow_logs.assert_called_once_with(
            "8", "/vpc/flow_log", "arn:aws:iam::112233445566:role/a_role"
        )

    def test_plan_create_flow_log_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(
                description="Create VPC flow log", details={"vpc_id": "vpc-1234", "log_group_name": "/vpc/flow_log"}
            ),
            generator.create_flow_log_action().plan(),
        )

    def test_apply_create_flow_log_delivery_role_action(self) -> None:
        a_role = generator.role(name="vpc_flow_log_role", policies=[policy(name="delivery_role_policy")])
        client = AwsVpcClientBuilder()
        client.with_create_role(a_role)
        client.with_policies(a_role.policies)
        client.with_attach_role_policy(a_role)

        generator.create_flow_log_delivery_role_action(iam=client.build().iam)._apply()
        client.iam.attach_role_policy.assert_called_once_with(a_role, a_role.policies[0].arn)

    def test_plan_create_flow_log_delivery_role_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Create delivery role for VPC flow log"),
            generator.create_flow_log_delivery_role_action().plan(),
        )

    def test_apply_delete_flow_log_delivery_role_action(self) -> None:
        client = Mock(spec=AwsIamClient)
        generator.delete_flow_log_delivery_role_action(iam=client)._apply()
        self.assertEqual([call.delete_role("vpc_flow_log_role")], client.mock_calls)

    def test_plan_delete_flow_log_delivery_role_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Delete delivery role for VPC flow log"),
            generator.delete_flow_log_delivery_role_action().plan(),
        )

    def test_apply_create_central_vpc_log_group_action(self) -> None:
        logs = Mock(spec=AwsLogsClient)
        generator.create_vpc_log_group_action(logs=logs)._apply()
        logs.create_log_group.assert_called_once_with("/vpc/flow_log")

    def test_plan_create_central_vpc_log_group_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Create central VPC log group"),
            generator.create_vpc_log_group_action().plan(),
        )

    def test_apply_delete_log_group_kms_key_alias_action(self) -> None:
        kms = Mock(spec=AwsKmsClient)
        generator.delete_log_group_kms_key_alias_action(kms=kms)._apply()
        kms.delete_alias.assert_called_once_with(name="an_alias")

    def test_plan_delete_log_group_kms_key_alias_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Delete log group kms key alias"),
            generator.delete_log_group_kms_key_alias_action().plan(),
        )

    def test_apply_create_log_group_kms_key_action(self) -> None:
        key = test_types_generator.key()
        with patch.object(AwsKmsClient, "create_key", return_value=key) as create_key:
            with patch.object(AwsKmsClient, "put_key_policy_statements") as put_key_policy_statements:
                expected_policy = [
                    {"account": key.account_id},
                    {"account": key.account_id, "region": key.region, "log_group_name": "/vpc/flow_log"},
                ]
                kms = AwsKmsClient(Mock())
                action = generator.create_log_group_kms_key_action(kms=kms)
                action._apply()

                create_key.assert_called_once_with(
                    alias="an_alias",
                    description="Autogenerated key for an_alias do not modify",
                )
                put_key_policy_statements.assert_called_once_with(key_id=key.id, statements=expected_policy)

    def test_plan_create_log_group_kms_key_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Create log group kms key"),
            generator.create_log_group_kms_key_action(kms=Mock()).plan(),
        )

    def test_apply_put_central_vpc_log_group_subscription_filter_action(self) -> None:
        logs = Mock(spec=AwsLogsClient)
        generator.put_vpc_log_group_subscription_filter_action(logs=logs)._apply()
        logs.put_subscription_filter.assert_called_once_with(
            log_group_name="/vpc/flow_log",
            filter_name="/vpc/flow_log_sub_filter",
            filter_pattern="[version, account_id, interface_id]",
            destination_arn="arn:aws:logs:::destination:central",
        )

    def test_plan_put_central_vpc_log_group_subscription_filter_action(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Put central VPC log group subscription filter"),
            generator.put_vpc_log_group_subscription_filter_action().plan(),
        )

    def test_apply_update_log_group_kms_key(self) -> None:
        expected_key_arn = generator.key().arn
        builder = AwsVpcClientBuilder()
        builder.with_default_key()
        builder.with_default_alias()
        client = builder.build()
        update_log_group_kms_key_action(logs=client.logs, kms=client.kms)._apply()

        builder.logs.associate_kms_key.assert_called_once_with(
            log_group_name="/vpc/flow_log", kms_key_arn=expected_key_arn
        )

    def test_plan_update_log_group_kms_key(self) -> None:
        self.assertEqual(
            ComplianceActionReport(description="Update log group kms key"),
            update_log_group_kms_key_action().plan(),
        )
