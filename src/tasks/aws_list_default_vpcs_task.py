from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


@dataclass
class AwsListDefaultVpcsTask(AwsTask):
    def __init__(self, account: Account, region: str):
        super().__init__("List VPCs", account, region=region)

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
        return {"Vpcs": client.ec2.list_default_vpcs()}
