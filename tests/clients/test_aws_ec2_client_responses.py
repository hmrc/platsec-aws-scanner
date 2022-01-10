from typing import Dict, Any, Sequence

from src.data.aws_ec2_types import FlowLog
from tests.test_types_generator import flow_log

EMPTY_FLOW_LOGS: Dict[str, Any] = {"FlowLogs": []}
FLOW_LOGS: Dict[str, Any] = {
    "FlowLogs": [
        {
            "FlowLogId": "fl-465fe654de123f54a",
            "FlowLogStatus": "ACTIVE",
            "LogGroupName": "/vpc/flow_log",
            "TrafficType": "ALL",
            "DeliverLogsPermissionArn": "a_role_arn",
            "LogDestination": "arn:aws:logs:us-east-1:111222333444:log-group:/vpc/flow_log",
            "LogDestinationType": "cloud-watch-logs",
            "LogFormat": "${version} ${account-id} ${interface-id}",
        },
        {
            "FlowLogId": "fl-4654ef654d12321cb",
            "FlowLogStatus": "ACTIVE",
            "TrafficType": "ACCEPT",
            "LogDestination": "arn:aws:s3:::some-bucket",
            "LogDestinationType": "s3",
            "LogFormat": "${start} ${end} ${action} ${log-status}",
        },
    ]
}
EXPECTED_FLOW_LOGS: Sequence[FlowLog] = [
    flow_log(
        id="fl-465fe654de123f54a",
        status="ACTIVE",
        log_destination="arn:aws:logs:us-east-1:111222333444:log-group:/vpc/flow_log",
        log_destination_type="cloud-watch-logs",
        log_group_name="/vpc/flow_log",
        traffic_type="ALL",
        deliver_log_role_arn="a_role_arn",
        log_format="${version} ${account-id} ${interface-id}",
        deliver_log_role=None,
    ),
    flow_log(
        id="fl-4654ef654d12321cb",
        status="ACTIVE",
        log_destination="arn:aws:s3:::some-bucket",
        log_destination_type="s3",
        log_group_name=None,
        traffic_type="ACCEPT",
        deliver_log_role_arn=None,
        log_format="${start} ${end} ${action} ${log-status}",
        deliver_log_role=None,
    ),
]

DELETE_FLOW_LOGS_SUCCESS: Dict[str, Any] = {"Unsuccessful": []}

DELETE_FLOW_LOGS_FAILURE: Dict[str, Any] = {
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

CREATE_FLOW_LOGS_SUCCESS: Dict[str, Any] = {"Unsuccessful": []}

CREATE_FLOW_LOGS_FAILURE: Dict[str, Any] = {
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
