from typing import List

from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.data.aws_ec2_types import VpcPeeringConnection
from src.data.aws_organizations_types import Account


class AwsVpcPeeringClient:
    def __init__(self, ec2: AwsEC2Client, org: AwsOrganizationsClient):
        self.ec2 = ec2
        self.org = org

    def list_vpc_peering_connections(self) -> List[VpcPeeringConnection]:
        return [self._enrich_pcx(pcx) for pcx in self.ec2.describe_vpc_peering_connections()]

    def _enrich_pcx(self, pcx: VpcPeeringConnection) -> VpcPeeringConnection:
        pcx.accepter = self._find_account_by_id(pcx.accepter_owner_id)
        pcx.requester = self._find_account_by_id(pcx.requester_owner_id)
        return pcx

    def _find_account_by_id(self, account_id: str) -> Account:
        return self.org.find_account_by_id(account_id) or Account(account_id, "unknown")
