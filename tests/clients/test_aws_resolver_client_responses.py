LIST_QUERY_LOG_CONFIGS = {
    "ResolverQueryLogConfigs": [
        {
            "Id": "someid",
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
            "Id": "someid",
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
        "Id": "someid",
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


LIST_RESOLVER_QUERY_LOG_CONFIG_ASSOCIATIONS_MANY_RESULTS = {
    "TotalCount": 10,
    "TotalFilteredCount": 0,
    "ResolverQueryLogConfigAssociations": [
        {
            "Id": "associations-id",
            "ResolverQueryLogConfigId": "config-id",
            "ResourceId": "vpc-id1",
            "Status": "ACTIVE",
            "Error": "NONE",
            "ErrorMessage": "string",
            "CreationTime": "string",
        },
        {
            "Id": "associations-id",
            "ResolverQueryLogConfigId": "config-id",
            "ResourceId": "vpc-id2",
            "Status": "ACTIVE",
            "Error": "NONE",
            "ErrorMessage": "string",
            "CreationTime": "string",
        },
        {
            "Id": "associations-id",
            "ResolverQueryLogConfigId": "resolver_query_log_config_id",
            "ResourceId": "vpc-id3",
            "Status": "ACTIVE",
            "Error": "NONE",
            "ErrorMessage": "string",
            "CreationTime": "string",
        },
    ],
}
