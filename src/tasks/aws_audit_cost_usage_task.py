from typing import Any, Dict
from dataclasses import dataclass
from src.data.aws_organizations_types import Account
from src.tasks.aws_cost_usage_task import AwsCostUsageTask
from src.clients.aws_cost_usage_client import AwsCostUsageClient


@dataclass
class AwsAuditCostUsageTask(AwsCostUsageTask):
    def __init__(self, account: Account, service: str, year: int, month: int) -> None:
        super().__init__(f"cost & usage of {service}", account)
        self._service = service
        self._year = year
        self._month = month

    def _run_task(self, client: AwsCostUsageClient) -> Dict[Any, Any]:
        return client.get_aws_cost_usage(self._service, self._year, self._month)
