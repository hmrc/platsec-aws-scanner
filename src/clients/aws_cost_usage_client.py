from logging import getLogger
from typing import List, Dict

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.clients import boto_try


class AwsCostUsageClient:
    def __init__(self, boto_cost_usage: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_usage = boto_cost_usage

    def get_aws_cost_usage(self, service: str, dates: dict) -> Dict:
        search_filter = (
            {
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": [
                        service,
                    ],
                    "MatchOptions": ["EQUALS"],
                }
            },
        )
        time_period = {"Start": dates["from"], "End": dates["to"]}

        return boto_try(
            lambda: self._cost_usage.get_cost_and_usage(
                TimePeriod=time_period,
                Filter=search_filter,
                Granularity="Monthly"
            ),
            None,
            f"unable to fetch cost usage for '{service}'",
        )
        # return boto_try(
        #     lambda: to_bucket_acl(self._s3.get_bucket_acl(Bucket=bucket)),
        #     BucketACL,
        #     f"unable to fetch access control list for bucket '{bucket}'",
        # )
        # return {}
