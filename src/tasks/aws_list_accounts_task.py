from dataclasses import dataclass
from typing import Any, Dict

from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.tasks.aws_organizations_task import AwsOrganizationsTask
from src.aws_scanner_config import AwsScannerConfig as Config


@dataclass
class AwsListAccountsTask(AwsOrganizationsTask):
    def __init__(self) -> None:
        super().__init__("list accounts in organization", Config().account_root())

    def _run_task(self, client: AwsOrganizationsClient) -> Dict[Any, Any]:
        return {"accounts": (client.get_all_accounts())}
