from typing import Any, Dict

from src.clients.composite.aws_cloudtrail_client import AwsCloudtrailClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditCloudtrailTask(AwsTask):
    def __init__(self, account: Account, region: str) -> None:
        super().__init__(description="audit Cloudtrail trails", account=account, region=region)

    def _run_task(self, client: AwsCloudtrailClient) -> Dict[Any, Any]:
        return {
            "trails": client.get_trails(),
            "log_group": client.get_cloudtrail_log_group(),
        }
