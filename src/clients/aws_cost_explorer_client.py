from logging import getLogger
from typing import Dict, Any, List
from datetime import date
import math

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from collections import defaultdict

from src.data.aws_scanner_exceptions import CostExplorerException


class AwsCostExplorerClient:
    def __init__(self, boto_cost_explorer: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cost_explorer = boto_cost_explorer

    def format_date(self, date: date) -> str:
        return f"{date.year}-{'%02d' % date.month}-{'%02d' % date.day}"

    def get_aws_cost_explorer(self, start_date: date, end_date: date) -> List[Dict[str, Any]]:
        time_period = {
            "Start": self.format_date(start_date),
            "End": self.format_date(end_date),
        }

        try:
            result = self._cost_explorer.get_cost_and_usage(
                TimePeriod=time_period,
                Granularity="MONTHLY",
                Metrics=["UsageQuantity", "AmortizedCost"],
                GroupBy=[
                    {"Type": "DIMENSION", "Key": "REGION"},
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                ],
            )
        except (BotoCoreError, ClientError) as err:
            raise CostExplorerException(f"unable to get cost usage : {err}")

        total_usage: defaultdict[tuple[str, str], float] = defaultdict(int)
        total_cost: defaultdict[tuple[str, str], float] = defaultdict(int)

        if "ResultsByTime" not in result:
            raise CostExplorerException("unable to get cost usage")
        else:
            for month in result["ResultsByTime"]:
                for item in month["Groups"]:
                    region = item["Keys"][0]
                    service = item["Keys"][1]
                    total_usage[(service, region)] = total_usage[(service, region)] + float(
                        item["Metrics"]["UsageQuantity"]["Amount"]
                    )
                    total_cost[(service, region)] = total_cost[(service, region)] + float(
                        item["Metrics"]["AmortizedCost"]["Amount"]
                    )

        report = []
        for key, value in total_usage.items():
            report.append(
                {
                    "service": key[0],
                    "region": key[1],
                    "dateRange": {"start": self.format_date(start_date), "end": self.format_date(end_date)},
                    "totalCost:": f'USD {"%d" % math.ceil(total_cost[key])}',
                    "totalUsage": str(math.ceil(value)),
                }
            )

        return report
