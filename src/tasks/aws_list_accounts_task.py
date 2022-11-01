from dataclasses import dataclass
from typing import Any, Dict

from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.tasks.aws_organizations_task import AwsOrganizationsTask
from src.aws_scanner_config import AwsScannerConfig as Config


@dataclass
class AwsListAccountsTask(AwsOrganizationsTask):
    def __init__(self, region: str) -> None:
        super().__init__(
            description="list accounts in organization",
            account=Config().organization_account(),
            region=region,
        )

    def _run_task(self, client: AwsOrganizationsClient) -> Dict[Any, Any]:
        return {"accounts": (client.get_all_accounts())}
