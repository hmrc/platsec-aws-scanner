from unittest import TestCase

from src.data.aws_ssm_types import Parameter, SSMDocument, to_parameter


class TestAwsSSMTypes(TestCase):
    def test_to_string_parameter(self) -> None:
        parameter = {"Name": "a_string_param", "Type": "String"}
        self.assertEqual(Parameter(name="a_string_param", type="String"), to_parameter(parameter))

    def test_to_secure_string_parameter(self) -> None:
        parameter = {"Name": "a_secure_string_param", "Type": "SecureString"}
        self.assertEqual(Parameter(name="a_secure_string_param", type="SecureString"), to_parameter(parameter))


def test_ssm_document_equals_true():
    document01 = SSMDocument(
        schema_version="1.0",
        description="ssm document 01",
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
            "shellProfile": {"windows": "date", "linux": "pwd;ls;pwd"},
        },
    )
    document02 = SSMDocument(
        schema_version="1.0",
        description="ssm document 02",
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
            "shellProfile": {"windows": "date", "linux": "pwd;ls;pwd"},
        },
    )
    assert document01 == document02


def test_ssm_document_equals_false():
    document01 = SSMDocument(
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
            "shellProfile": {"windows": "date", "linux": "pwd;ls;pwd"},
        },
    )
    document02 = SSMDocument(
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
            "shellProfile": {"windows": "date", "linux": "pwd;ls;pwd"},
        },
    )
    assert document01 != document02
    assert document01 != "someStr"
