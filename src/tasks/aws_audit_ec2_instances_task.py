from dataclasses import dataclass
from typing import Any, Dict

from src.clients.aws_ec2_client import AwsEC2Client
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditEc2InstancesTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("audit EC2 instances", account)

    def _run_task(self, client: AwsEC2Client) -> Dict[Any, Any]:
        return {"ec2_instances": client.list_instances()}
