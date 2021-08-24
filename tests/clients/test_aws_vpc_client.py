from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, patch

from src.clients.composite.aws_vpc_client import AwsVpcClient

from tests.test_types_generator import policy, role


class TestAwsVpcClient(AwsScannerTestCase):
    def test_find_flow_log_delivery_role(self) -> None:
        delivery_role = role(name="the_delivery_role")
        ec2, iam, logs = Mock(), Mock(), Mock()
        with patch.object(iam, "get_role", side_effect=lambda n: delivery_role if n == "vpc_flow_log_role" else None):
            self.assertEqual(delivery_role, AwsVpcClient(ec2, iam, logs).find_flow_log_delivery_role())

    def test_flow_log_delivery_role_compliant(self) -> None:
        delivery_role = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[
                policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]}),
                policy(document={"Statement": [{"Effect": "Something"}]}),
            ],
        )
        ec2, iam, logs = Mock(), Mock(), Mock()
        self.assertTrue(AwsVpcClient(ec2, iam, logs).is_flow_log_delivery_role_compliant(delivery_role))

    def test_flow_log_delivery_role_not_compliant(self) -> None:
        invalid_assume_policy = role(
            assume_policy={"Statement": [{"Action": "sts:other"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]})],
        )
        invalid_policy_document = role(
            assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]},
            policies=[policy(document={"Statement": [{"Effect": "Allow", "Action": ["logs:bla"]}]})],
        )
        missing_policy_document = role(assume_policy={"Statement": [{"Action": "sts:AssumeRole"}]}, policies=[])
        ec2, iam, logs = Mock(), Mock(), Mock()
        self.assertFalse(AwsVpcClient(ec2, iam, logs).is_flow_log_delivery_role_compliant(invalid_assume_policy))
        self.assertFalse(AwsVpcClient(ec2, iam, logs).is_flow_log_delivery_role_compliant(invalid_policy_document))
        self.assertFalse(AwsVpcClient(ec2, iam, logs).is_flow_log_delivery_role_compliant(missing_policy_document))
