DESCRIBE_TRAILS_RESPONSE_EMPTY = {"Trails": []}

DESCRIBE_TRAILS_RESPONSE_ONE = {
    "trailList": [
        {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        },
    ]
}

DESCRIBE_TRAILS_RESPONSE_TWO = {
    "trailList": [
        {
            "Name": "dummy-trail-1",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789012",
        },
        {
            "Name": "dummy-trail-2",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
            "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:us-east-2:123456789012:key/12345678-1234-1234-1234-123456789013",
        },
    ]
}
