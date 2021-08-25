from tests.test_types_generator import flow_log

EMPTY_FLOW_LOGS = {"FlowLogs": []}
FLOW_LOGS = {
    "FlowLogs": [
        {
            "FlowLogId": "fl-465fe654de123f54a",
            "FlowLogStatus": "ACTIVE",
            "LogGroupName": "/vpc/flow_log",
            "TrafficType": "ALL",
            "DeliverLogsPermissionArn": "a_role_arn",
            "LogDestination": "arn:aws:logs:us-east-1:111222333444:log-group:/vpc/flow_log",
            "LogFormat": "${version} ${account-id} ${interface-id}",
        },
        {
            "FlowLogId": "fl-4654ef654d12321cb",
            "FlowLogStatus": "ACTIVE",
            "TrafficType": "ACCEPT",
            "LogDestination": "arn:aws:s3:::some-bucket",
            "LogFormat": "${start} ${end} ${action} ${log-status}",
        },
    ]
}
EXPECTED_FLOW_LOGS = [
    flow_log(
        id="fl-465fe654de123f54a",
        status="ACTIVE",
        log_group_name="/vpc/flow_log",
        traffic_type="ALL",
        deliver_log_role_arn="a_role_arn",
        log_format="${version} ${account-id} ${interface-id}",
        deliver_log_role=None,
    ),
    flow_log(
        id="fl-4654ef654d12321cb",
        status="ACTIVE",
        log_group_name=None,
        traffic_type="ACCEPT",
        deliver_log_role_arn=None,
        log_format="${start} ${end} ${action} ${log-status}",
        deliver_log_role=None,
    ),
]

DELETE_FLOW_LOGS_SUCCESS = {"Unsuccessful": []}

DELETE_FLOW_LOGS_FAILURE = {
    "Unsuccessful": [
        {
            "Error": {
                "Code": "InvalidFlowLogId.NotFound",
                "Message": "These flow log ids in the input list are not found: [TotalCount: 1] bad-fl",
            },
            "ResourceId": "bad-fl",
        },
    ]
}

CREATE_FLOW_LOGS_SUCCESS = {"Unsuccessful": []}

CREATE_FLOW_LOGS_FAILURE = {
    "Unsuccessful": [
        {
            "Error": {
                "Code": "InvalidVpcId.NotFound",
                "Message": "Unknown resource vpc-00112233344556677",
            },
            "ResourceId": "bad-vpc",
        },
    ]
}
