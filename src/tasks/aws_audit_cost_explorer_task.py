from typing import Any, Dict
from dataclasses import dataclass
from src.data.aws_organizations_types import Account
from src.clients.aws_cost_explorer_client import AwsCostExplorerClient
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditCostExplorerTask(AwsTask):
    def __init__(self, account: Account, service: str, year: int, month: int) -> None:
        super().__init__(f"cost & usage of {service}", account)
        self._service = service
        self._year = year
        self._month = month

    def _run_task(self, client: AwsCostExplorerClient) -> Dict[Any, Any]:
        return client.get_aws_cost_explorer(self._service, self._year, self._month)
