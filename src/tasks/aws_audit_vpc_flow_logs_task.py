from dataclasses import dataclass
from typing import Any, Dict

from src.clients.aws_ec2_client import AwsEC2Client
from src.data.aws_organizations_types import Account
from src.tasks.aws_ec2_task import AwsEC2Task
from src.data.aws_ec2_actions import enforcement_actions


@dataclass
class AwsAuditVPCFlowLogsTask(AwsEC2Task):
    def __init__(self, account: Account, enforce: bool) -> None:
        super().__init__("audit VPC flow logs compliance", account, enforce)

    def _run_task(self, client: AwsEC2Client) -> Dict[Any, Any]:
        vpcs = client.list_vpcs()
        actions = [action for vpc in vpcs for action in enforcement_actions(vpc)]
        return {"vpcs": client.list_vpcs(), "enforcement_actions": client.apply(actions) if self.enforce else actions}
