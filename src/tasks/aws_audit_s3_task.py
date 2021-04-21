from dataclasses import dataclass
from typing import Any, Dict

from src.clients.aws_s3_client import AwsS3Client
from src.data.aws_organizations_types import Account
from src.data.aws_s3_types import Bucket
from src.tasks.aws_s3_task import AwsS3Task


@dataclass
class AwsAuditS3Task(AwsS3Task):
    def __init__(self, account: Account) -> None:
        super().__init__("audit S3 bucket compliance", account)

    def _run_task(self, client: AwsS3Client) -> Dict[Any, Any]:
        return {"buckets": list(map(lambda bucket: self._enrich_bucket(client, bucket), client.list_buckets()))}

    @staticmethod
    def _enrich_bucket(client: AwsS3Client, bucket: Bucket) -> Bucket:
        bucket.encryption = client.get_bucket_encryption(bucket.name)
        return bucket
