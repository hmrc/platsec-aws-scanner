from dataclasses import dataclass
import json
from logging import getLogger
from typing import Any, Dict

from src.clients.aws_ssm_client import AwsSSMClient
from src.data.aws_organizations_types import Account
from src.data.aws_scanner_exceptions import GetSSMDocumentException
from src.data.aws_ssm_types import SSMDocument
from src.tasks.aws_ssm_task import AwsSSMTask

SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME = "SSM-SessionManagerRunShell"
SESSION_MANAGER_RUN_SHELL_JSON_FILE = "src/resources/SessionManagerRunShell.json"


@dataclass
class AwsAuditSSMDocumentTask(AwsSSMTask):
    def __init__(self, account: Account, region: str) -> None:
        self._logger = getLogger(self.__class__.__name__)
        super().__init__(description="Audit SSM RunShell Document", account=account, region=region)

    def _run_task(self, client: AwsSSMClient) -> Dict[str, Any]:
        try:
            observed = client.get_document(name=SESSION_MANAGER_RUN_SHELL_DOCUMENT_NAME)
        except GetSSMDocumentException as e:
            self._logger.error(e)
            observed = SSMDocument(schema_version="", description="", session_type="", inputs={})

        with open(SESSION_MANAGER_RUN_SHELL_JSON_FILE) as f:
            expected = json.load(f)

        try:
            observed_max_session_duration = int(observed.inputs.get("maxSessionDuration", ""))
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
                            "compliant": observed.inputs.get("s3BucketName", "") == expected["inputs"]["s3BucketName"],
                            "message": "S3 bucket name should be mdtp-ssm-session-manager-audit-logs",
                        },
                        "s3EncryptionEnabled": {
                            "compliant": observed.inputs.get("s3EncryptionEnabled", False)
                            == expected["inputs"]["s3EncryptionEnabled"],
                            "message": "S3 encryption should be enabled",
                        },
                        "maxSessionDuration": {
                            "compliant": max_session_duration_is_compliant,
                            "message": "maxSessionDuration should be less than or equal to 120 mins",
                        },
                        "shellProfile": {
                            "compliant": observed.inputs.get("shellProfile", "") == expected["inputs"]["shellProfile"],
                            "message": "shellProfile should match expected config",
                        },
                    },
                }
            ]
        }
