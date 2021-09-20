DESCRIBE_KEY = {
    "KeyMetadata": {
        "AWSAccountId": "112233445566",
        "KeyId": "1234abcd",
        "Arn": "arn:aws:kms:us-east-1:112233445566:key/1234abcd",
        "Description": "some key desc",
        "KeyState": "Enabled",
    }
}

GET_KEY_POLICY = {"Policy": '{\n  "Statement" : [ {\n    "Effect" : "Allow"}\n    \n  ]\n}'}

CREATE_KEY = {
    "KeyMetadata": {
        "AWSAccountId": "999888666555",
        "KeyId": "5678ffff",
        "Arn": "arn:aws:kms:us-east-2:999888666555:key/5678ffff",
        "Description": "brand new key",
        "KeyState": "Enabled",
    }
}

LIST_ALIASES_PAGES = [
    {
        "Aliases": [
            {
                "AliasName": "alias/alias-1",
                "AliasArn": "arn:aws:kms:us-east-1:111222333444:alias/alias-1",
                "TargetKeyId": "1234-5678",
            },
        ]
    },
    {
        "Aliases": [
            {"AliasName": "alias/alias-2", "AliasArn": "arn:aws:kms:us-east-1:111222333444:alias/alias-2"},
        ]
    },
]
