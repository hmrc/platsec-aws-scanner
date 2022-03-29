from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_ec2_types import VpcPeeringConnection
from src.data.aws_organizations_types import Account
from src.tasks.aws_vpc_task import AwsVpcTask


class AwsAuditVpcPeeringTask(AwsVpcTask):
    def __init__(self, account: Account):
        super().__init__("audit VPC peering connections", account, False)

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
        accounts_map = {acc.identifier: acc for acc in client.org.get_all_accounts()}
        return {
            "vpc_peering_connections": [
                self._enrich_pcx(pcx, accounts_map) for pcx in client.ec2.describe_vpc_peering_connections()
            ]
        }

    def _find_account_by_id(self, accounts_map: Dict[str, Account], account_id: str) -> Account:
        return accounts_map.get(account_id) or Account(account_id, "unknown")

    def _enrich_pcx(self, pcx: VpcPeeringConnection, accounts_map: Dict[str, Account]) -> VpcPeeringConnection:
        pcx.accepter_account = self._find_account_by_id(accounts_map, pcx.accepter_owner_id)
        pcx.requester_account = self._find_account_by_id(accounts_map, pcx.requester_owner_id)
        return pcx
