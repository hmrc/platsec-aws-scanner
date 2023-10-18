from unittest import TestCase
from unittest.mock import Mock
from src.data.aws_ssm_types import SSMDocument
from src.tasks.aws_audit_ssm_document_task import AwsAuditSSMDocumentTask

from src.tasks.aws_list_ssm_parameters_task import AwsListSSMParametersTask

from tests.test_types_generator import (
    account,
    secure_string_parameter,
    string_list_parameter,
    string_parameter,
)
from tests.test_types_generator import TEST_REGION


def test_aws_audit_ssm_document_compliance_true():
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "",
            "s3KeyPrefix": "",
            "s3EncryptionEnabled": True,
            "cloudWatchLogGroupName": "",
            "cloudWatchEncryptionEnabled": True,
            "cloudWatchStreamingEnabled": False,
            "kmsKeyId": "",
            "runAsEnabled": False,
            "runAsDefaultUser": "",
            "idleSessionTimeout": "",
            "maxSessionDuration": "",
            "shellProfile": {
                "windows": "date",
                "linux": "pwd;ls;pwd"
            }
        }
    )

    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    expected = {"ssm_document_audit_compliant": True}

    assert expected == task_report

def test_aws_audit_ssm_document_compliance_false():
    document = SSMDocument(
        schema_version="1.0",
        description="ssm document",
        session_type="Standard_Stream",
        inputs={
            "s3BucketName": "my-bucket",
            "s3KeyPrefix": "my-key-prefix",
            "s3EncryptionEnabled": True,
            "cloudWatchLogGroupName": "",
            "cloudWatchEncryptionEnabled": True,
            "cloudWatchStreamingEnabled": False,
            "kmsKeyId": "",
            "runAsEnabled": False,
            "runAsDefaultUser": "",
            "idleSessionTimeout": "",
            "maxSessionDuration": "",
            "shellProfile": {
                "windows": "date",
                "linux": "pwd;ls;pwd"
            }
        }
    )

    ssm_client = Mock(get_document=Mock(return_value=document))
    task_report = AwsAuditSSMDocumentTask(account=account(), region=TEST_REGION)._run_task(ssm_client)
    expected = {"ssm_document_audit_compliant": True}

    assert expected != task_report
