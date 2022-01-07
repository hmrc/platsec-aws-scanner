from typing import Dict, Any, Sequence

from src.data.aws_ec2_types import FlowLog
from tests.test_types_generator import flow_log

EMPTY_FLOW_LOGS: Dict[str, Any] = {"FlowLogs": []}
FLOW_LOGS: Dict[str, Any] = {
    "FlowLogs": [
        {
            "FlowLogId": "fl-465fe654de123f54a",
            "FlowLogStatus": "ACTIVE",
            "LogDestination": "central_log_bucket",
            "LogDestinationType": "s3",
            "TrafficType": "ALL",
            "DeliverLogsPermissionArn": "a_role_arn",
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
EXPECTED_FLOW_LOGS: Sequence[FlowLog] = [
    flow_log(
        id="fl-465fe654de123f54a",
        status="ACTIVE",
        log_destination="central_log_bucket",
        log_destination_type="s3",
        traffic_type="ALL",
        log_format="${version} ${account-id} ${interface-id}",
    ),
    flow_log(
        id="fl-4654ef654d12321cb",
        status="ACTIVE",
        log_destination="arn:aws:s3:::some-bucket",
        log_destination_type=None,
        traffic_type="ACCEPT",
        log_format="${start} ${end} ${action} ${log-status}",
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
