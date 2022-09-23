from tests.test_types_generator import log_group, subscription_filter, tag

LIST_QUERY_LOG_CONFIGS = {
    "ResolverQueryLogConfigs": [
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
