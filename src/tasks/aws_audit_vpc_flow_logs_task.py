from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditVPCFlowLogsTask(AwsTask):
    def __init__(self, account: Account, enforce: bool, with_subscription_filter: bool, skip_tags: bool) -> None:
        super().__init__("audit VPC flow logs compliance", account)
        self.with_subscription_filter = with_subscription_filter
        self.enforce = enforce
        self.skip_tags = skip_tags

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
        vpcs = client.list_vpcs()
        actions = client.enforcement_flow_log_actions(vpcs, self.with_subscription_filter, self.skip_tags)
        if self.enforce:
            apply = [a.apply() for a in actions]
            return {"vpcs": vpcs, "enforcement_actions": apply}
        else:
            plans = [a.plan() for a in actions]
            return {"vpcs": vpcs, "enforcement_actions": plans}
