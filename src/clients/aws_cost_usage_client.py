from logging import getLogger
from typing import List, Dict
from datetime import date
import math

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError


class CostUsageException(Exception):
    pass


class AwsCostUsageClient:
    def __init__(self, boto_cost_usage: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_usage = boto_cost_usage

    def get_aws_cost_usage(self, service: str, year: int, month: int) -> Dict:

        try:
            search_filter = {
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": [
                        service,
                    ],
                    "MatchOptions": ["EQUALS"],
                }
            }

            today = date.today()

            time_period = {
                "Start": f"{year}-{'%02d' % month}-01",
                "End": f"{today.year}-{'%02d' % today.month}-{'%02d' % today.day}",
            }
            metrics = ["UsageQuantity", "AmortizedCost"]

            result = self._cost_usage.get_cost_and_usage(
                TimePeriod=time_period, Filter=search_filter, Granularity="MONTHLY", Metrics=metrics
            )

            total_usage = 0
            total_cost = 0
            for item in result["ResultsByTime"]:
                total_usage = total_usage + float(item["Total"]["UsageQuantity"]["Amount"])
                total_cost = total_cost + float(item["Total"]["AmortizedCost"]["Amount"])
            total_cost = result["ResultsByTime"][0]["Total"]["AmortizedCost"]["Unit"] + " " + str(math.ceil(total_cost))

            return {
                "Service": service,
                "DateRange": time_period,
                "TotalCost:": total_cost,
                "TotalUsage": str(math.ceil(total_usage)),
            }

        except Exception as err:
            raise CostUsageException(f"unable to get cost usage data for {service}: {err}")
