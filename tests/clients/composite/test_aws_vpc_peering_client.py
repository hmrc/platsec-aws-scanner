from unittest.mock import Mock

from typing import Optional

from src.clients.composite.aws_vpc_peering_client import AwsVpcPeeringClient
from src.data.aws_organizations_types import Account

from tests.test_types_generator import account, vpc_peering_connection

acc_1 = account(identifier="1", name="the account 1")
acc_2 = account(identifier="2", name="the account 2")


def mock_find_account_by_id(account_id: str) -> Optional[Account]:
    return {acc_1.identifier: acc_1, acc_2.identifier: acc_2}.get(account_id)


def test_list_vpc_peering_connections() -> None:
    peering_connections = [
        vpc_peering_connection(id="cx-1", accepter_owner_id="1", requester_owner_id="3", accepter=None, requester=None),
        vpc_peering_connection(id="cx-2", accepter_owner_id="4", requester_owner_id="2", accepter=None, requester=None),
    ]

    client = AwsVpcPeeringClient(
        ec2=Mock(describe_vpc_peering_connections=Mock(return_value=peering_connections)),
        org=Mock(find_account_by_id=Mock(side_effect=mock_find_account_by_id)),
    )

    assert client.list_vpc_peering_connections() == peering_connections
    assert peering_connections[0].accepter == acc_1
    assert peering_connections[0].requester == account(identifier="3", name="unknown")
    assert peering_connections[1].accepter == account(identifier="4", name="unknown")
    assert peering_connections[1].requester == acc_2
