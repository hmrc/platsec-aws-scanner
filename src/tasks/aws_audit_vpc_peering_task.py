from typing import Any, Dict

from src.clients.composite.aws_vpc_peering_client import AwsVpcPeeringClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditVpcPeeringTask(AwsTask):
    def __init__(self, account: Account, region: str):
        super().__init__(description="audit VPC peering connections", account=account, region=region)

    def _run_task(self, client: AwsVpcPeeringClient) -> Dict[Any, Any]:
        return {"vpc_peering_connections": client.list_vpc_peering_connections()}
