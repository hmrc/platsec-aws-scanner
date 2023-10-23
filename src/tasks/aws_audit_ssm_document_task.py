from dataclasses import dataclass
import json
from typing import Any, Dict

from src.clients.aws_ssm_client import AwsSSMClient
from src.data.aws_organizations_types import Account
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
            expected = json.load(f)

        try:
            observed_max_session_duration = int(observed.inputs["maxSessionDuration"])
            max_session_duration_is_compliant = observed_max_session_duration <= int(
                expected["inputs"]["maxSessionDuration"]
            )
        except ValueError:
            max_session_duration_is_compliant = False

        return {
            "documents": [
                {
                    "name": SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME,
                    "compliancy": {
                        "s3BucketName": {
                            "compliant": observed.inputs["s3BucketName"] == expected["inputs"]["s3BucketName"],
                            "message": "S3 bucket name should be mdtp-ssm-session-manager-audit-logs",
                        },
                        "s3EncryptionEnabled": {
                            "compliant": observed.inputs["s3EncryptionEnabled"]
                            == expected["inputs"]["s3EncryptionEnabled"],
                            "message": "S3 encryption should be enabled",
                        },
                        "maxSessionDuration": {
                            "compliant": max_session_duration_is_compliant,
                            "message": "maxSessionDuration should be less than or equal to 120 mins",
                        },
                        "shellProfile": {
                            "compliant": observed.inputs["shellProfile"] == expected["inputs"]["shellProfile"],
                            "message": "shellProfile should match expected config",
                        },
                    },
                }
            ]
        }
