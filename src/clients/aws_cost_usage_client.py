from logging import getLogger
from typing import List, Dict

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.clients import boto_try


class AwsCostUsageClient:
    def __init__(self, boto_cost_usage: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_usage = boto_cost_usage

    @staticmethod
    def get_aws_cost_usage(service: str) -> Dict:
        # return boto_try(
        #     lambda: to_bucket_acl(self._s3.get_bucket_acl(Bucket=bucket)),
        #     BucketACL,
        #     f"unable to fetch access control list for bucket '{bucket}'",
        # )
        return {}
