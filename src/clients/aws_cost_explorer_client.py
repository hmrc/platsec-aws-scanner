from logging import getLogger
from typing import Dict, Any
from datetime import date
import math

from botocore.client import BaseClient
from src.data.aws_scanner_exceptions import CostExplorerException


class AwsCostExplorerClient:
    def __init__(self, boto_cost_explorer: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_explorer = boto_cost_explorer

    def get_aws_cost_explorer(self, service: str, year: int, month: int) -> Dict[str, Any]:

        try:
            today = date.today()

            time_period = {
                "Start": f"{year}-{'%02d' % month}-01",
                "End": f"{today.year}-{'%02d' % today.month}-{'%02d' % today.day}",
            }

            result = self._cost_explorer.get_cost_and_usage(
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
                "service": service,
                "dateRange": {"start": time_period["Start"], "end": time_period["End"]},
                "totalCost:": total_str,
                "totalUsage": str(math.ceil(total_usage)),
            }

        except Exception as err:
            raise CostExplorerException(f"unable to get cost usage data for {service}: {err}")
