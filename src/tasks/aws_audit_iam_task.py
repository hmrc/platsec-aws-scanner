from typing import Any, Dict

from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditIamTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("audit iam compliance", account)

    def _run_task(self) -> Dict[Any, Any]:
        raise NotImplementedError("this is an abstract class")
