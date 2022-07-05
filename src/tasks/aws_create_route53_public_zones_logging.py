from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.tasks.aws_audit_route53_public_zones_task import AwsAuditRoute53PublicZonesTask
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


@dataclass
class AwsCreateRoute53PublicZonesLogsTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("Create Route53 public zones logs", account)

    def _run_task(self, client: AwsRoute53Client) -> Dict[Any, Any]:

        public_zones: Dict[Any, Any] = {}
        hostedzonesTask = AwsAuditRoute53PublicZonesTask(self._account)

        hostedzones = hostedzonesTask._run_task(client)
        for zone in hostedzones.values():
            if zone.queryLog == "":
                client.create_query_logging_config(zone.id, "arn:aws:logs:us-east-1:" + self.account.identifier + ":log-group:/aws/route53/" + zone.name + ".")

        return public_zones
