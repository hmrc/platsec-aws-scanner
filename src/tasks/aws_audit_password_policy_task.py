from typing import Any, Dict

from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditPasswordPolicyTask(AwsTask):
    def __init__(self, account: Account, enforce: bool) -> None:
        super().__init__("audit password policy compliance", account)
        self.enforce = enforce

    def _run_task(self, client: AwsIamClient) -> Dict[Any, Any]:
        return {"password_policy": client.get_account_password_policy()}
