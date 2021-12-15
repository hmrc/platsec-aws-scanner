from typing import Any, Dict

from src.clients.composite.aws_central_logging_client import AwsCentralLoggingClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditCentralLoggingTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__("audit central logging account", account)

    def _run_task(self, client: AwsCentralLoggingClient) -> Dict[Any, Any]:
        return {
            "events_bucket": client.get_event_bucket(),
            "events_cmk": client.get_event_cmk(),
            "org_accounts": client.get_all_accounts(),
        }
