from logging import getLogger
from typing import Dict, Any
from datetime import date
import math

from botocore.client import BaseClient
from src.data.aws_scanner_exceptions import CostUsageException


class AwsCostUsageClient:
    def __init__(self, boto_cost_usage: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_usage = boto_cost_usage

    def get_aws_cost_usage(self, service: str, year: int, month: int) -> Dict[str, Any]:

        try:
            today = date.today()

            time_period = {
                "Start": f"{year}-{'%02d' % month}-01",
                "End": f"{today.year}-{'%02d' % today.month}-{'%02d' % today.day}",
            }

            result = self._cost_usage.get_cost_and_usage(
                TimePeriod=time_period,
                Filter={
                    "Dimensions": {
                        "Key": "SERVICE",
                        "Values": [
                            service,
                        ],
                        "MatchOptions": ["EQUALS"],
                    }
                },
                Granularity="MONTHLY",
                Metrics=["UsageQuantity", "AmortizedCost"],
            )

            total_usage = total_cost = 0.00

            for item in result["ResultsByTime"]:
                total_usage = total_usage + float(item["Total"]["UsageQuantity"]["Amount"])
                total_cost = total_cost + float(item["Total"]["AmortizedCost"]["Amount"])

            total_str = f'{result["ResultsByTime"][0]["Total"]["AmortizedCost"]["Unit"]} {"%d" % math.ceil(total_cost)}'

            return {
                "Service": service,
                "DateRange": time_period,
                "TotalCost:": total_str,
                "TotalUsage": str(math.ceil(total_usage)),
            }

        except Exception as err:
            raise CostUsageException(f"unable to get cost usage data for {service}: {err}")
