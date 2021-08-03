from dataclasses import dataclass
from typing import Any, Dict

from src.clients.aws_ec2_client import AwsEC2Client
from src.data.aws_organizations_types import Account
from src.tasks.aws_ec2_task import AwsEC2Task


@dataclass
class AwsAuditVPCFlowLogsTask(AwsEC2Task):
    def __init__(self, account: Account, enforce: bool) -> None:
        super().__init__("audit VPC flow logs compliance", account, enforce)

    def _run_task(self, client: AwsEC2Client) -> Dict[Any, Any]:
        return {"vpcs": client.list_vpcs()}
