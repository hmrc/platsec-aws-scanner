from tests.test_types_generator import log_group, subscription_filter, tag

LIST_QUERY_LOG_CONFIGS = {
    "ResolverQueryLogConfigs": [
        {
            "Id": 1234567890,
            "OwnerId": 1234567890,
            "Status": "CREATED",
            "ShareStatus": "NOT_SHARED",
            "AssociationCount": 123,
            "Arn": "arn",
            "Name": "scanner_query_log_name",
            "DestinationArn": "log_group_arn",
            "CreatorRequestId": "203582384",
            "CreationTime": "a date string?",
        }
    ]
}
