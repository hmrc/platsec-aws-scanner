from src.data.aws_ec2_types import FlowLog

EMPTY_FLOW_LOGS = {"FlowLogs": []}
FLOW_LOGS = {
    "FlowLogs": [
        {
            "FlowLogId": "fl-465fe654de123f54a",
            "FlowLogStatus": "ACTIVE",
            "TrafficType": "ALL",
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
    FlowLog(
        id="fl-465fe654de123f54a",
        status="ACTIVE",
        traffic_type="ALL",
        log_destination="arn:aws:logs:us-east-1:111222333444:log-group:/vpc/flow_log",
        log_format="${version} ${account-id} ${interface-id}",
    ),
    FlowLog(
        id="fl-4654ef654d12321cb",
        status="ACTIVE",
        traffic_type="ACCEPT",
        log_destination="arn:aws:s3:::some-bucket",
        log_format="${start} ${end} ${action} ${log-status}",
    ),
]
