from dataclasses import dataclass
from typing import Any, Dict
from src.clients.composite.aws_route53_client import AwsRoute53Client

from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask
from tests.test_types_generator import route53Zone

@dataclass
class AwsAuditRoute53PublicZonesTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("audit Route53 public zones", account)

    def _run_task(self, client: AwsRoute53Client) -> list[route53Zone]:
        public_zones = [route53Zone(id="/hostedzone/AAAABBBBCCCCDD", name= "name1", privateZone= False)]
        return  public_zones
