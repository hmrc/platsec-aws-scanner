from unittest.mock import Mock

import tests.clients.composite.test_aws_rout53_client_responses as response
from tests.test_types_generator import create_route53_public_zones_logs_task


def test_create_route53_public_zones_logs_task_success() -> None:

    route53_client = Mock()
    route53_client.list_hosted_zones = Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES)
    route53_client.list_query_logging_configs = Mock(
        side_effect=[response.EXPECTED_QUERY_LOG, response.EXPECTED_EMPTY_QUERY_LOG]
    )

    route53_client.create_query_logging_config = Mock(return_value="returned value")

    res = create_route53_public_zones_logs_task()

    res._run_task(route53_client)

    route53_client.create_query_logging_config.assert_called()
