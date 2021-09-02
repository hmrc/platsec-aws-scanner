from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_vpc_task import AwsVpcTask


@dataclass
class AwsAuditVPCFlowLogsTask(AwsVpcTask):
    def __init__(self, account: Account, enforce: bool) -> None:
        super().__init__("audit VPC flow logs compliance", account, enforce)

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
        vpcs = client.list_vpcs()
        actions = [action for vpc in vpcs for action in client.enforcement_actions(vpc)]
        return {"vpcs": vpcs, "enforcement_actions": client.apply(actions) if self.enforce else actions}
