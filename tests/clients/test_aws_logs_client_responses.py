from tests.test_types_generator import log_group, subscription_filter

DESCRIBE_LOG_GROUPS = {"logGroups": [{"logGroupName": "/vpc/flow_log"}, {"logGroupName": "/vpc/flow_log_2"}]}

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

EXPECTED_LOG_GROUPS = [
    log_group(
        name="/vpc/flow_log",
        subscription_filters=[
            subscription_filter(
                filter_name="VpcFlowLogsForward",
                log_group_name="/vpc/flow_log",
                filter_pattern="[version, account_id, interface_id]",
                destination_arn="arn:aws:logs:us-east-1:223322332233:destination:SomeDestination",
            )
        ],
    ),
    log_group(
        name="/vpc/flow_log_2",
        subscription_filters=[
            subscription_filter(
                filter_name="SecondFilter",
                log_group_name="/vpc/flow_log_2",
                filter_pattern="[account_id]",
                destination_arn="arn:aws:logs:us-east-1:223322332233:destination:OtherDestination",
            )
        ],
    ),
]
