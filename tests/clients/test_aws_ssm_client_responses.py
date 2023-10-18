from src.data.aws_ssm_types import SSMDocument
from tests.test_types_generator import secure_string_parameter, string_list_parameter, string_parameter

DESCRIBE_PARAMETERS_PAGE_1 = {
    "Parameters": [
        {"Name": "some_top_level_parameter", "Type": "String", "Version": 1},
        {"Name": "/secure/param/with/path", "Type": "SecureString", "Version": 1},
    ],
    "NextToken": "token_for_params_page_2",
}
DESCRIBE_PARAMETERS_PAGE_2 = {
    "Parameters": [
        {"Name": "/list/param/with/path", "Type": "StringList", "Version": 1},
    ]
}
EXPECTED_LIST_PARAMETERS = [
    string_parameter(name="some_top_level_parameter"),
    secure_string_parameter(name="/secure/param/with/path"),
    string_list_parameter(name="/list/param/with/path"),
]

RESPONSE_GET_DOCUMENT = {
    "Name": "SSM-SessionManagerRunShell",
    "CreatedDate": "2023-10-16T16:56:28.598000+01:00",
    "DocumentVersion": "1",
    "Status": "Active",
    "Content": (
        '{\n  "schemaVersion": "1.0",'
        '\n  "description": "Document to hold regional settings for Session Manager",'
        '\n  "sessionType": "Standard_Stream",'
        '\n  "inputs": {'
        '\n    "s3BucketName": "",'
        '\n    "s3KeyPrefix": "",'
        '\n    "s3EncryptionEnabled": true,'
        '\n    "cloudWatchLogGroupName": "",'
        '\n    "cloudWatchEncryptionEnabled": true,'
        '\n    "cloudWatchStreamingEnabled": false,'
        '\n    "kmsKeyId": "",'
        '\n    "runAsEnabled": false,'
        '\n    "runAsDefaultUser": "",'
        '\n    "idleSessionTimeout": "",'
        '\n    "maxSessionDuration": "",'
        '\n    "shellProfile": {\n      "windows": "date",\n      "linux": "pwd;ls;pwd"\n    }'
        "\n  }"
        "\n}"
    ),
    "DocumentType": "Session",
    "DocumentFormat": "JSON",
}

EXPECTED_SSM_DOCUMENT = SSMDocument(
    schema_version="1.0",
    description="",
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
