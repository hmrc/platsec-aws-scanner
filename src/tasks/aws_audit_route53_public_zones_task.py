from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask
import  src.data.aws_route53_types as route53Type

@dataclass
class AwsAuditRoute53PublicZonesTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("audit Route53 public zones", account)

    def _run_task(self, client: AwsRoute53Client) -> list[route53Type.Route53Zone]:
        zonedict = {
            "zoneId": "/hostedzone/AAAABBBBCCCCDD",
            "name": "name1",
            "privateZone": False
        }
        public_zones = [route53Type.to_route53Zone(zonedict)]
        return  public_zones
