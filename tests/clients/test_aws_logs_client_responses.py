from tests.test_types_generator import log_group, subscription_filter, tag

DESCRIBE_LOG_GROUPS = {
    "logGroups": [
        {"logGroupName": "lg_1", "retentionInDays": 3},
        {"logGroupName": "lg_2", "kmsKeyId": "9", "storedBytes": 1234},
    ]
}

DESCRIBE_LOG_GROUPS_SINGLE_WITH_KMS = {
    "logGroups": [
        {"logGroupName": "lg_2", "kmsKeyId": "9", "storedBytes": 1234},
    ]
}

DESCRIBE_SUBSCRIPTION_FILTERS_SINGLE = [
    {
        "subscriptionFilters": [
            {
                "filterName": "SecondFilter",
                "logGroupName": "/vpc/flow_log_2",
                "filterPattern": "[account_id]",
                "destinationArn": "arn:aws:logs:us-east-1:223322332233:destination:OtherDestination",
            }
        ]
    },
]


DESCRIBE_SUBSCRIPTION_FILTERS = [
    {
        "subscriptionFilters": [
            {
                "filterName": "VpcFlowLogsForward",
                "logGroupName": "/vpc/flow_log",
                "filterPattern": "[version, account_id, interface_id]",
                "destinationArn": "arn:aws:logs:us-east-1:223322332233:destination:SomeDestination",
            }
        ]
    },
    {
        "subscriptionFilters": [
            {
                "filterName": "SecondFilter",
                "logGroupName": "/vpc/flow_log_2",
                "filterPattern": "[account_id]",
                "destinationArn": "arn:aws:logs:us-east-1:223322332233:destination:OtherDestination",
            }
        ]
    },
]

LIST_TAGS_LOG_GROUP = [
    {
        "tags": {
            "a_tag": "a_value",
            "another_tag": "another_value",
        }
    },
    {"tags": {}},
]

EXPECTED_LOG_GROUPS = [
    log_group(
        name="lg_1",
        retention_days=3,
        subscription_filters=[
            subscription_filter(
                filter_name="VpcFlowLogsForward",
                log_group_name="/vpc/flow_log",
                filter_pattern="[version, account_id, interface_id]",
                destination_arn="arn:aws:logs:us-east-1:223322332233:destination:SomeDestination",
            )
        ],
        tags=[tag("a_tag", "a_value"), tag("another_tag", "another_value")],
    ),
    log_group(
        name="lg_2",
        kms_key_id="9",
        retention_days=None,
        stored_bytes=1234,
        subscription_filters=[
            subscription_filter(
                filter_name="SecondFilter",
                log_group_name="/vpc/flow_log_2",
                filter_pattern="[account_id]",
                destination_arn="arn:aws:logs:us-east-1:223322332233:destination:OtherDestination",
            )
        ],
        tags=[],
    ),
]
