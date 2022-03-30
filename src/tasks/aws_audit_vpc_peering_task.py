from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_ec2_types import VpcPeeringConnection
from src.data.aws_organizations_types import Account
from src.tasks.aws_vpc_task import AwsVpcTask


class AwsAuditVpcPeeringTask(AwsVpcTask):
    def __init__(self, account: Account):
        super().__init__("audit VPC peering connections", account, False)

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
        return {
            "vpc_peering_connections": [
                self._enrich_pcx(pcx, client) for pcx in client.ec2.describe_vpc_peering_connections()
            ]
        }

    def _enrich_pcx(self, pcx: VpcPeeringConnection, client: AwsVpcClient) -> VpcPeeringConnection:
        pcx.accepter_account = self._find_account_by_id(pcx.accepter_owner_id, client)
        pcx.requester_account = self._find_account_by_id(pcx.requester_owner_id, client)
        return pcx

    def _find_account_by_id(self, account_id: str, client: AwsVpcClient) -> Account:
        return client.org.find_account_by_id(account_id) or Account(account_id, "unknown")
