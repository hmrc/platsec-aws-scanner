from dataclasses import dataclass
import json
from typing import Any, Dict

from src.clients.aws_ssm_client import AwsSSMClient
from src.data.aws_organizations_types import Account
from src.data.aws_ssm_types import SSMDocument
from src.tasks.aws_ssm_task import AwsSSMTask

SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME = "SSM-SessionManagerRunShell"
SESSION_MANAGER_RUN_SHELL_JSON_FILE = "src/resources/SessionManagerRunShell.json"


@dataclass
class AwsAuditSSMDocumentTask(AwsSSMTask):
    def __init__(self, account: Account, region: str) -> None:
        super().__init__(description="Audit SSM RunShell Document", account=account, region=region)

    def _run_task(self, client: AwsSSMClient) -> Dict[str, Any]:
        observed = client.get_document(name=SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME)
        with open(SESSION_MANAGER_RUN_SHELL_JSON_FILE) as f:
            data = json.load(f)
            expected = SSMDocument(
                schema_version=data["schemaVersion"],
                description=data["description"],
                session_type=data["sessionType"],
                inputs=data["inputs"],
            )
        return {"documents": [{"name": SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME, "compliant": expected == observed}]}
