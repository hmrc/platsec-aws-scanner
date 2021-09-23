from logging import getLogger
from typing import List, Dict
from datetime import date

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError


class CostUsageException(Exception):
    pass


class AwsCostUsageClient:
    def __init__(self, boto_cost_usage: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_usage = boto_cost_usage

    def get_aws_cost_usage(self, service: str, year: int, month: int) -> Dict:
        self._logger.info(f"service {service}")
        try:
            search_filter = {
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": [
                        service,
                    ],
                    "MatchOptions": ["EQUALS"]
                }
            }

            today = date.today()

            time_period = {"Start": f"{year}-{'%02d' % month}-01", "End": f"{today.year}-{'%02d' % today.month}-01"}
            metrics = ["AmortizedCost", "UsageQuantity"]
            group_by = [
                {
                    'Type': 'DIMENSION',
                    'Key': 'SERVICE'
                },
            ]

            return self._cost_usage.get_cost_and_usage(
                TimePeriod=time_period, Filter=search_filter, Granularity="MONTHLY", Metrics=metrics, GroupBy=group_by
            )

        except Exception as err:
            raise CostUsageException(f"unable to get cost usage data for {service}: {err}")
