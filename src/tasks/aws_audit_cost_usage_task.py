from typing import Any, Dict
from dataclasses import dataclass
from src.tasks.aws_task import AwsTask
from src.data.aws_organizations_types import Account
from src.tasks.aws_cost_usage_task import AwsCostUsageTask
from src.clients.aws_cost_usage_client import AwsCostUsageClient


@dataclass
class AwsAuditCostUsageTask(AwsCostUsageTask):
    def __init__(self, account: Account,  service: str, year: str, month: str) -> None:
        super().__init__(f"cost & usage of {service}", account)
        self._service = service
        self._year = year
        self._month = month

    def _run_task(self, client: AwsCostUsageClient) -> Dict[Any, Any]:
        return client.get_aws_cost_usage(self._service, self._year, self._month)
    

    # @staticmethod
    # def _enrich_bucket(client: AwsS3Client, bucket: Bucket) -> Bucket:
    #     bucket.acl = client.get_bucket_acl(bucket.name)
    #     bucket.content_deny = client.get_bucket_content_deny(bucket.name)
    #     bucket.cors = client.get_bucket_cors(bucket.name)
    #     bucket.data_tagging = client.get_bucket_data_tagging(bucket.name)
    #     bucket.encryption = client.get_bucket_encryption(bucket.name)
    #     bucket.lifecycle = client.get_bucket_lifecycle(bucket.name)
    #     bucket.logging = client.get_bucket_logging(bucket.name)
    #     bucket.mfa_delete = client.get_bucket_mfa_delete(bucket.name)
    #     bucket.public_access_block = client.get_bucket_public_access_block(bucket.name)
    #     bucket.secure_transport = client.get_bucket_secure_transport(bucket.name)
    #     bucket.versioning = client.get_bucket_versioning(bucket.name)
    #     return bucket
