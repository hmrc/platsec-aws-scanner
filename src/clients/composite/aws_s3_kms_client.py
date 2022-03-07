from logging import getLogger


from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_s3_client import AwsS3Client
from src.data.aws_s3_types import Bucket

from typing import List


class AwsS3KmsClient:
    def __init__(self, s3: AwsS3Client, kms: AwsKmsClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._s3 = s3
        self._kms = kms

    def list_buckets(self) -> List[Bucket]:
        return self._s3.list_buckets()

    def enrich_bucket(self, bucket: Bucket) -> Bucket:
        bucket.acl = self._s3.get_bucket_acl(bucket.name)
        bucket.content_deny = self._s3.get_bucket_content_deny(bucket.name)
        bucket.cors = self._s3.get_bucket_cors(bucket.name)
        bucket.data_tagging = self._s3.get_bucket_data_tagging(bucket.name)
        bucket.encryption = self._s3.get_bucket_encryption(bucket.name)
        bucket.lifecycle = self._s3.get_bucket_lifecycle(bucket.name)
        bucket.logging = self._s3.get_bucket_logging(bucket.name)
        bucket.mfa_delete = self._s3.get_bucket_mfa_delete(bucket.name)
        bucket.public_access_block = self._s3.get_bucket_public_access_block(bucket.name)
        bucket.secure_transport = self._s3.get_bucket_secure_transport(bucket.name)
        bucket.versioning = self._s3.get_bucket_versioning(bucket.name)
        bucket.kms_key = self._kms.find_key(bucket.encryption.key)

        return bucket
