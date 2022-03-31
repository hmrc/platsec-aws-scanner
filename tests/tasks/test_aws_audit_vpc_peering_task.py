from unittest.mock import Mock

from tests.test_types_generator import audit_vpc_peering_task, vpc_peering_connection


def test_run_task() -> None:
    peering_connections = [vpc_peering_connection(id="pcx-1"), vpc_peering_connection(id="pcx-2")]
    vpc_peering_client = Mock(list_vpc_peering_connections=Mock(return_value=peering_connections))
    assert audit_vpc_peering_task()._run_task(vpc_peering_client) == {"vpc_peering_connections": peering_connections}
