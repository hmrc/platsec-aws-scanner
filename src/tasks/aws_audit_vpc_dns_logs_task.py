from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_vpc_client import AwsVpcClient
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditVPCDnsLogsTask(AwsTask):
    def __init__(self, account: Account, enforce: bool, with_subscription_filter: bool) -> None:
        super().__init__("audit VPC dns logs compliance", account)
        self.with_subscription_filter = with_subscription_filter
        self.enforce = enforce

    def _run_task(self, client: AwsVpcClient) -> Dict[Any, Any]:
       pass
