from typing import Any, Dict

from src.clients.aws_iam_audit_client import AwsIamAuditClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditIamTask(AwsTask):
    def __init__(self, account: Account, region: str) -> None:
        super().__init__(description="audit iam compliance", account=account, region=region)

    def _run_task(self, client: AwsIamAuditClient) -> Dict[Any, Any]:
        keys = []
        for user in client.list_users():
            access_keys = client.list_access_keys(user)
            for key in access_keys:
                key.last_used = client.get_access_key_last_used(key)
                keys.append(key)
        return {"iam_access_keys": keys}
