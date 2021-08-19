from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsVpcTask(AwsTask):
    def __init__(self, description: str, account: Account, enforce: bool):
        super().__init__(description, account)
        self._enforce = enforce

    @property
    def enforce(self) -> bool:
        return self._enforce

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
