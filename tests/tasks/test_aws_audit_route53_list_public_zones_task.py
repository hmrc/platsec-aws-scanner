from unittest.mock import Mock

from tests.test_types_generator import route53Zone
import tests.clients.composite.test_aws_rout53_client_responses as response
from tests.test_types_generator import audit_route53_public_zones_task

def test_audit_route53_public_zones_task() -> None:
    public_zones = [route53Zone(id="/hostedzone/AAAABBBBCCCCDD", name= "name1", privateZone= False)]
    route53_client = Mock(list_hosted_zones=Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES))
    res = audit_route53_public_zones_task()._run_task(route53_client)

    print(type(res))
    assert res ==   public_zones
