from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditRoute53QueryLogsTask(AwsTask):
    def __init__(
        self,
        account: Account,
        enforce: bool,
        with_subscription_filter: bool,
        skip_tags: bool,
        region: str,
    ) -> None:
        super().__init__(
            description="audit Route53 query logs compliance",
            account=account,
            region=region,
        )
        self.with_subscription_filter = with_subscription_filter
        self.enforce = enforce
        self.target_account = account
        self.skip_tags = skip_tags

    def _run_task(self, client: AwsRoute53Client) -> Dict[Any, Any]:
        hostedZones = client._route53.list_hosted_zones()
        actions = client.enforcement_actions(
            self.target_account,
            hostedZones,
            self.with_subscription_filter,
            self.skip_tags,
        )

        if self.enforce:
            apply = [a.apply() for a in actions]
            return {"hostedZones": hostedZones, "enforcement_actions": apply}
        else:
            plans = [a.plan() for a in actions]
            return {"hostedZones": hostedZones, "enforcement_actions": plans}
