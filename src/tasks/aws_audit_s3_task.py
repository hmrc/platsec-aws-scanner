from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.data.aws_organizations_types import Account
from src.data.aws_s3_types import Bucket
from src.tasks.aws_s3_task import AwsS3Task


@dataclass
class AwsAuditS3Task(AwsS3Task):
    def __init__(self, account: Account) -> None:
        super().__init__("audit S3 bucket compliance", account)

    def _run_task(self, client: AwsS3KmsClient) -> Dict[Any, Any]:
        return {
            "buckets": list(
                map(lambda bucket: self._set_compliance(client.enrich_bucket(bucket)), client.list_buckets())
            )
        }

    def _set_compliance(self, bucket: Bucket) -> CheckedBucket:
        # we want these enabled
        bucket.content_deny.compliant = bucket.content_deny.enabled
        bucket.encryption.compliant = bucket.encryption.enabled

        if bucket.kms_key:
            bucket.kms_key.compliant = bucket.kms_key.rotation_enabled

        bucket.data_tagging.compliant = bucket.data_tagging.expiry != "unset" and bucket.data_tagging.sensitivity != "unset"

        # we want these disabled
        bucket.acl.compliant = bucket.acl.authenticated_users_enabled is False and bucket.acl.all_users_enabled is False
        bucket.cors.compliant = not bucket.cors.enabled

        return bucket
