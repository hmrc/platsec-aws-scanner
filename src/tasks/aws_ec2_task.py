from typing import Any, Dict

from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask
from src.clients.aws_ec2_client import AwsEC2Client


class AwsEC2Task(AwsTask):
    def __init__(self, description: str, account: Account, enforce: bool):
        super().__init__(description, account)
        self._enforce = enforce

    @property
    def enforce(self) -> bool:
        return self._enforce

    def _run_task(self, client: AwsEC2Client) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
