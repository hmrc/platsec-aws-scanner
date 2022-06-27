from unittest.mock import Mock

from tests.test_types_generator import route53Zone
import tests.clients.composite.test_aws_rout53_client_responses as response
from tests.test_types_generator import audit_route53_public_zones_task
import  src.data.aws_route53_types as route53Type

def test_audit_route53_public_zones_task_returns_public_zone() -> None:
    public_zones = [route53Zone(id="/hostedzone/AAAABBBBCCCCDD", name= "public.aws.scanner.gov.uk.", privateZone= False)]
    route53_client = Mock(list_hosted_zones=Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES))
    res = audit_route53_public_zones_task()._run_task(route53_client)
    assert res ==   public_zones

def test_audit_route53_public_zones_task_returns_empty() -> None:
    public_zones : list[route53Type.Route53Zone] =[]
    route53_client = Mock(list_hosted_zones=Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES_PRIVATE))
    res = audit_route53_public_zones_task()._run_task(route53_client)
    assert res ==   public_zones

def test_audit_route53_public_zones_task_returns_public_zones() -> None:
    public_zones = [route53Zone(id="/hostedzone/AAAABBBBCCCCDD", name= "public.aws.scanner.gov.uk.", privateZone= False), route53Zone(id="/hostedzone/EEEEFFFFGGGGHH", name= "private.aws.scanner.gov.uk.",privateZone= False) ]
    route53_client = Mock(list_hosted_zones=Mock(return_value=response.EXPECTED_LIST_HOSTED_ZONES_PUBLIC))
    res = audit_route53_public_zones_task()._run_task(route53_client)
    assert res ==   public_zones