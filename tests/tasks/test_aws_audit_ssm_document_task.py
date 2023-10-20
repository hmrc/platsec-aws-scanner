from unittest.mock import Mock
from src.data.aws_ssm_types import SSMDocument
from src.tasks.aws_audit_ssm_document_task import AwsAuditSSMDocumentTask

from tests.test_types_generator import account
from tests.test_types_generator import TEST_REGION


def test_aws_audit_ssm_document_compliance_true() -> None:
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "mdtp-ssm-session-manager-audit-logs",
            "s3KeyPrefix": "123456789012",
            "s3EncryptionEnabled": True,
            "maxSessionDuration": "120",
            "shellProfile": {
                "linux": "cd ~ && /bin/bash && echo 'This session will be automatically terminated after 2 hours'"
            },
        },
    )

    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    print(task_report)
    expected = {"documents": [{"name": "SSM-SessionManagerRunShell", "compliant": True}]}

    assert expected == task_report


def test_aws_audit_ssm_document_compliance_false() -> None:
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "mdtp-ssm-session-manager-audit-logs",
            "s3KeyPrefix": "123456789012",
            "s3EncryptionEnabled": True,
            "maxSessionDuration": "1440",
            "shellProfile": {
                "linux": "cd ~ && /bin/bash && echo 'This session will be automatically terminated after 2 hours'"
            },
        },
    )

    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    expected = {"documents": [{"name": "SSM-SessionManagerRunShell", "compliant": True}]}

    assert expected != task_report
