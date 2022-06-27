from unittest.mock import Mock, patch
from typing import Any, Dict

from tests.test_types_generator import route53Zone
import tests.clients.composite.test_aws_rout53_client_responses as response
from tests.test_types_generator import audit_route53_public_zones_task

@patch.multiple('route53_client',
                list_hosted_zones=Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES),
                list_query_logging_configs=Mock(return_value=response.EXPECTED_QUERY_LOG)
)
def test_audit_route53_public_zones_task_returns_public_zone(mocked_route53_client) -> None:
    public_zones: Dict[Any, Any] = {
        "/hostedzone/AAAABBBBCCCCDD": route53Zone(
            id="/hostedzone/AAAABBBBCCCCDD", name="public.aws.scanner.gov.uk.")
    }

    res = audit_route53_public_zones_task()._run_task(mocked_route53_client)
    assert res == public_zones
