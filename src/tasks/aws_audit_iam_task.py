from typing import Any, Dict

from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditIamTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("audit iam compliance", account)

    def _run_task(self, client: AwsIamClient) -> Dict[Any, Any]:
        keys = []
        for user in client.list_users():
            access_keys = client.list_access_keys(user)
            for key in access_keys:
                key.last_used = client.get_access_key_last_used(key)
                keys.append(key)
        return {"iam_access_keys": keys}
