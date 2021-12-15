from logging import getLogger
from typing import Optional

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_s3_client import AwsS3Client
from src.data.aws_s3_types import Bucket
from src.data.aws_kms_types import Key


class AwsCentralLoggingClient:
    def __init__(self, s3: AwsS3Client, kms: AwsKmsClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._s3 = s3
        self._kms = kms

    def get_event_bucket(self) -> Optional[Bucket]:
        bucket_name = self._config.cloudtrail_logs_bucket()
        bucket_policy = self._s3.get_bucket_policy(bucket_name)
        return Bucket(name=bucket_name, policy=bucket_policy) if bucket_policy else None

    def get_event_cmk(self) -> Optional[Key]:
        return self._kms.find_key(self._config.cloudtrail_event_key_id())
