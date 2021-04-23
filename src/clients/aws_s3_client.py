from logging import getLogger
from typing import List

from botocore.client import BaseClient

from src.clients import boto_try
from src.data.aws_s3_types import (
    Bucket,
    BucketEncryption,
    BucketLogging,
    BucketPublicAccessBlock,
    BucketSecureTransport,
    to_bucket,
    to_bucket_encryption,
    to_bucket_logging,
    to_bucket_public_access_block,
    to_bucket_secure_transport,
)


class AwsS3Client:
    def __init__(self, boto_s3: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._s3 = boto_s3

    def list_buckets(self) -> List[Bucket]:
        return [to_bucket(bucket) for bucket in self._s3.list_buckets()["Buckets"]]

    def get_bucket_encryption(self, bucket: str) -> BucketEncryption:
        self._logger.debug(f"fetching encryption config for bucket '{bucket}'")
        return boto_try(
            lambda: to_bucket_encryption(self._s3.get_bucket_encryption(Bucket=bucket)),
            BucketEncryption,
            f"unable to fetch encryption config for bucket '{bucket}'",
        )

    def get_bucket_logging(self, bucket: str) -> BucketLogging:
        self._logger.debug(f"fetching server access logging config for bucket '{bucket}'")
        return boto_try(
            lambda: to_bucket_logging(self._s3.get_bucket_logging(Bucket=bucket)),
            BucketLogging,
            f"unable to fetch server access logging config for bucket '{bucket}'",
        )

    def get_bucket_secure_transport(self, bucket: str) -> BucketSecureTransport:
        self._logger.debug(f"fetching policy for bucket '{bucket}'")
        return boto_try(
            lambda: to_bucket_secure_transport(self._s3.get_bucket_policy(Bucket=bucket)),
            BucketSecureTransport,
            f"unable to fetch policy for bucket '{bucket}'",
        )

    def get_bucket_public_access_block(self, bucket: str) -> BucketPublicAccessBlock:
        self._logger.debug(f"fetching public access block for bucket '{bucket}'")
        return boto_try(
            lambda: to_bucket_public_access_block(self._s3.get_public_access_block(Bucket=bucket)),
            BucketPublicAccessBlock,
            f"unable to fetch public access block for bucket '{bucket}'",
        )
