from typing import Any, Dict
from dataclasses import dataclass
from datetime import date
from src.data.aws_organizations_types import Account
from src.clients.aws_cost_explorer_client import AwsCostExplorerClient
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditCostExplorerTask(AwsTask):
    def __init__(self, account: Account, today: date, region: str) -> None:
        super().__init__(
            description=f"cost & usage in acount {account}",
            account=account,
            region=region,
        )
        self.today = today

    def _run_task(self, client: AwsCostExplorerClient) -> Dict[Any, Any]:
        # 1 year is the max AWS allows for this query
        start_date = date(self.today.year - 1, self.today.month, 1)

        report = client.get_aws_cost_explorer(start_date=start_date, end_date=self.today)
        return {"cost_explorer": report}
