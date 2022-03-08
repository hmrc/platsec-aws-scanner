from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_s3_task import AwsS3Task


@dataclass
class AwsAuditS3Task(AwsS3Task):
    def __init__(self, account: Account) -> None:
        super().__init__("audit S3 bucket compliance", account)

    def _run_task(self, client: AwsS3KmsClient) -> Dict[Any, Any]:
        return {"buckets": list(map(lambda bucket: client.enrich_bucket(bucket), client.list_buckets()))}
