from logging import getLogger
from typing import List, Dict

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError


class CostUsageException(Exception):
    pass


class AwsCostUsageClient:

    def __init__(self, boto_cost_usage: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_usage = boto_cost_usage

    def get_aws_cost_usage(self, service: str, dates: dict) -> Dict:
        try:
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

            return self._cost_usage.get_cost_and_usage(
                    TimePeriod=time_period,
                    Filter=search_filter,
                    Granularity="Monthly"
                )

        except (BotoCoreError, ClientError) as err:
            raise CostUsageException(f"unable to get cost usage data for {service}: {err}")
