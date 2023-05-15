from unittest import TestCase
from unittest.mock import Mock

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.tasks.aws_list_default_vpcs_task import AwsListDefaultVpcsTask
from src.data.aws_ec2_types import Vpc
from tests.test_types_generator import account
from tests.test_types_generator import TEST_REGION


class TestAwsListDefaultVpcsTask(TestCase):
    def test_run_task(self) -> None:
        vpcs = [{"VpcId": "vpc-12312e654bf654d12"}, {"VpcId": "vpc-984a4654b65465e12"}]
        ec2_client = AwsEC2Client(Mock(describe_vpcs=Mock(return_value={"Vpcs": vpcs})), account=account())
        vpc_client = AwsVpcClient(
            ec2=ec2_client, iam=Mock(), logs=Mock(), config=Mock(), log_group=Mock(), resolver=Mock()
        )
        self.assertEqual(
            {"Vpcs": [Vpc("vpc-12312e654bf654d12"), Vpc("vpc-984a4654b65465e12")]},
            AwsListDefaultVpcsTask(account(), region=TEST_REGION)._run_task(vpc_client),
        )
