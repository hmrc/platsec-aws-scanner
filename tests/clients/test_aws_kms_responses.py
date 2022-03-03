DESCRIBE_KEY = {
    "KeyMetadata": {
        "AWSAccountId": "112233445566",
        "KeyId": "1234abcd",
        "Arn": "arn:aws:kms:us-east-1:112233445566:key/1234abcd",
        "Description": "some key desc",
        "KeyState": "Enabled",
    }
}

LIST_RESOURCE_TAGS = {
    "Tags": [
        {"TagKey": "tag1", "TagValue": "value1"},
        {"TagKey": "tag2", "TagValue": "value2"},
    ],
    "NextMarker": "string",
    "Truncated": False,
}


GET_KEY_POLICY = {"Policy": '{\n  "Statement" : [ {\n    "Effect" : "Allow"}\n    \n  ]\n}'}


GET_KEY_ROTATION_STATUS = {
    "KeyRotationEnabled": True,
}
