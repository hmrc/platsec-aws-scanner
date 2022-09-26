LIST_QUERY_LOG_CONFIGS = {
    "ResolverQueryLogConfig": [
        {
            "Id": 1234567890,
            "OwnerId": 1234567890,
            "Status": "CREATED",
            "ShareStatus": "NOT_SHARED",
            "AssociationCount": 123,
            "Arn": "somearn",
            "Name": "scanner_query_log_name",
            "DestinationArn": "some_destination_arn",
            "CreatorRequestId": "203582384",
            "CreationTime": "a date string?",
        },
        {
            "Id": 1234567890,
            "OwnerId": 12345627890,
            "Status": "CREATED",
            "ShareStatus": "NOT_SHARED",
            "AssociationCount": 123,
            "Arn": "somearn2",
            "Name": "scanner_query_log_name2",
            "DestinationArn": "some_destination_arn2",
            "CreatorRequestId": "2035823843",
            "CreationTime": "a date string?",
        },
    ]
}

CREATE_QUERY_LOG_CONFIG = {
    "ResolverQueryLogConfig": {
        "Id": "string",
        "OwnerId": "string",
        "Status": "CREATING",
        "ShareStatus": "NOT_SHARED",
        "AssociationCount": 123,
        "Arn": "some arn that you can use later",
        "Name": "scanner_query_log_name",
        "DestinationArn": "some_destination_arn",
        "CreatorRequestId": "string",
        "CreationTime": "string",
    }
}
