from unittest.mock import Mock
from src.data.aws_ssm_types import SSMDocument
from src.tasks.aws_audit_ssm_document_task import AwsAuditSSMDocumentTask

from tests.test_types_generator import account
from tests.test_types_generator import TEST_REGION

REPORT_FULL_COMPLIANCE = {
    "documents": [
        {
            "name": "SSM-SessionManagerRunShell",
            "compliancy": {
                "s3BucketName": {
                    "compliant": True,
                    "message": "S3 bucket name should be mdtp-ssm-session-manager-audit-logs",
                },
                "s3EncryptionEnabled": {"compliant": True, "message": "S3 encryption should be enabled"},
                "maxSessionDuration": {
                    "compliant": True,
                    "message": "maxSessionDuration should be less than or equal to 120 mins",
                },
                "shellProfile": {"compliant": True, "message": "shellProfile should match expected config"},
            },
        }
    ]
}


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

    assert REPORT_FULL_COMPLIANCE == task_report


def test_aws_audit_ssm_document_compliance_on_low_max_session_duration() -> None:
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "mdtp-ssm-session-manager-audit-logs",
            "s3KeyPrefix": "123456789012",
            "s3EncryptionEnabled": True,
            "maxSessionDuration": "90",
            "shellProfile": {
                "linux": "cd ~ && /bin/bash && echo 'This session will be automatically terminated after 2 hours'"
            },
        },
    )

    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)

    assert REPORT_FULL_COMPLIANCE == task_report


def test_aws_audit_ssm_document_compliance_on_high_max_session_duration() -> None:
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "mdtp-ssm-session-manager-audit-logs",
            "s3KeyPrefix": "123456789012",
            "s3EncryptionEnabled": True,
            "maxSessionDuration": "121",
            "shellProfile": {
                "linux": "cd ~ && /bin/bash && echo 'This session will be automatically terminated after 2 hours'"
            },
        },
    )
    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    expected = {
        "documents": [
            {
                "name": "SSM-SessionManagerRunShell",
                "compliancy": {
                    "s3BucketName": {
                        "compliant": True,
                        "message": "S3 bucket name should be mdtp-ssm-session-manager-audit-logs",
                    },
                    "s3EncryptionEnabled": {"compliant": True, "message": "S3 encryption should be enabled"},
                    "maxSessionDuration": {
                        "compliant": False,
                        "message": "maxSessionDuration should be less than or equal to 120 mins",
                    },
                    "shellProfile": {"compliant": True, "message": "shellProfile should match expected config"},
                },
            }
        ]
    }

    assert expected == task_report


def test_aws_audit_ssm_document_compliance_on_s3_config_items() -> None:
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "fake-ssm-session-manager-audit-logs",
            "s3KeyPrefix": "123456789012",
            "s3EncryptionEnabled": False,
            "maxSessionDuration": "120",
            "shellProfile": {
                "linux": "cd ~ && /bin/bash && echo 'This session will be automatically terminated after 2 hours'"
            },
        },
    )

    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    expected = {
        "documents": [
            {
                "name": "SSM-SessionManagerRunShell",
                "compliancy": {
                    "s3BucketName": {
                        "compliant": False,
                        "message": "S3 bucket name should be mdtp-ssm-session-manager-audit-logs",
                    },
                    "s3EncryptionEnabled": {"compliant": False, "message": "S3 encryption should be enabled"},
                    "maxSessionDuration": {
                        "compliant": True,
                        "message": "maxSessionDuration should be less than or equal to 120 mins",
                    },
                    "shellProfile": {"compliant": True, "message": "shellProfile should match expected config"},
                },
            }
        ]
    }

    assert expected == task_report


def test_aws_audit_ssm_document_compliance_on_shell_profile() -> None:
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "mdtp-ssm-session-manager-audit-logs",
            "s3KeyPrefix": "123456789012",
            "s3EncryptionEnabled": True,
            "maxSessionDuration": "120",
            "shellProfile": {"linux": "cd ~ && /bin/bash && echo 'Hello World!'"},
        },
    )
    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    expected = {
        "documents": [
            {
                "name": "SSM-SessionManagerRunShell",
                "compliancy": {
                    "s3BucketName": {
                        "compliant": True,
                        "message": "S3 bucket name should be mdtp-ssm-session-manager-audit-logs",
                    },
                    "s3EncryptionEnabled": {"compliant": True, "message": "S3 encryption should be enabled"},
                    "maxSessionDuration": {
                        "compliant": True,
                        "message": "maxSessionDuration should be less than or equal to 120 mins",
                    },
                    "shellProfile": {"compliant": False, "message": "shellProfile should match expected config"},
                },
            }
        ]
    }

    assert expected == task_report
