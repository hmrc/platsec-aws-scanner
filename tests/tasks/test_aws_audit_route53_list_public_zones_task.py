from unittest.mock import Mock, call
from typing import Any, Dict

import tests.clients.composite.test_aws_rout53_client_responses as response
from tests.test_types_generator import audit_route53_public_zones_task
from src.data.aws_route53_types import Route53Zone


def test_audit_route53_public_zones_task_returns_public_zone() -> None:
    public_zones: Dict[Any, Any] = {
        "/hostedzone/AAAABBBBCCCCDD": Route53Zone(
            id="/hostedzone/AAAABBBBCCCCDD",
            name="public.aws.scanner.gov.uk.",
            privateZone=False,
            queryLog="arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/public.aws.scanner.gov.uk.",
        ),
        "/hostedzone/IIIIIIILLLLLLL": Route53Zone(
            id="/hostedzone/IIIIIIILLLLLLL",
            name="public.aws.scanner.gov.uk.",
            privateZone=False,
            queryLog="",
        ),
    }

    route53_client = Mock()
    route53_client.list_hosted_zones = Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES)
    route53_client.list_query_logging_configs = Mock(
        side_effect=[response.EXPECTED_QUERY_LOG, response.EXPECTED_EMPTY_QUERY_LOG]
    )

    res = audit_route53_public_zones_task()._run_task(route53_client)
    assert res == public_zones

    route53_client.list_query_logging_configs.assert_has_calls([call("AAAABBBBCCCCDD"), call("IIIIIIILLLLLLL")])
    assert route53_client.list_query_logging_configs.call_count == 2
