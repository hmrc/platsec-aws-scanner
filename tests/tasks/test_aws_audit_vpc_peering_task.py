from unittest.mock import Mock

from tests.test_types_generator import account, audit_vpc_peering_task, vpc_peering_connection


def test_run_task() -> None:
    acc_a = account(identifier="1234", name="the account a")
    acc_b = account(identifier="5678", name="the account b")
    unknown_account = account(identifier="9999", name="unknown")

    peering_connections = [
        vpc_peering_connection(
            id="pcx-1",
            accepter_owner_id="1234",
            requester_owner_id="9999",
            accepter_account=None,
            requester_account=None,
        ),
        vpc_peering_connection(
            id="pcx-2",
            accepter_owner_id="9999",
            requester_owner_id="5678",
            accepter_account=None,
            requester_account=None,
        ),
    ]

    vpc_client = Mock(
        ec2=Mock(describe_vpc_peering_connections=Mock(return_value=peering_connections)),
        org=Mock(get_all_accounts=Mock(return_value=[acc_a, acc_b])),
    )

    outcome = audit_vpc_peering_task()._run_task(vpc_client)

    assert outcome == {"vpc_peering_connections": peering_connections}
    assert peering_connections[0].accepter_account == acc_a
    assert peering_connections[0].requester_account == unknown_account
    assert peering_connections[1].accepter_account == unknown_account
    assert peering_connections[1].requester_account == acc_b
