from typing import Any, Dict
from dataclasses import dataclass
from src.data.aws_cloudtrail_types import Trail
from src.data.aws_organizations_types import Account
from src.clients.aws_cloudtrail_audit_client import AwsCloudtrailAuditClient
from src.tasks.aws_task import AwsTask


@dataclass
class AwsAuditCloudtrailTask(AwsTask):
    def __init__(self, account: Account) -> None:
        super().__init__(f"Audit Cloudtrails", account)

    def _run_task(self, client: AwsCloudtrailAuditClient) -> Dict[Any, Any]:
        return {"cloudtrails": list(map(lambda trail: self._enrich_trail(client, trail), client.get_trails()))}

    @staticmethod
    def _enrich_trail(client: AwsCloudtrailAuditClient, trail: Trail) -> Trail:
        trail.logfile_validation = client.check_logfile_validation_enabled(trail)
        trail.logfile_encryption_at_rest = client.check_logfile_encryption(trail)
        return trail
