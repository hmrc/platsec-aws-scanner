import datetime
from typing import Dict, Any, Sequence

from src.data.aws_ec2_types import FlowLog
from tests.test_types_generator import flow_log, instance, vpc_peering_connection

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

DESCRIBE_VPC_PEERING_CONNECTIONS_PAGES = [
    {
        "VpcPeeringConnections": [
            {
                "AccepterVpcInfo": {"OwnerId": "222333444555", "VpcId": "vpc-a1b2c3d4"},
                "RequesterVpcInfo": {"OwnerId": "121212121212", "VpcId": "vpc-48d45821"},
                "Status": {"Code": "active", "Message": "Active"},
                "VpcPeeringConnectionId": "pcx-1a1a1a1a",
            },
            {
                "AccepterVpcInfo": {"OwnerId": "787878787878", "VpcId": "vpc-f1f1f1f1f1f1f1f1f"},
                "RequesterVpcInfo": {"OwnerId": "33566455788", "VpcId": "vpc-c9d8e7f4"},
                "Status": {"Code": "active", "Message": "Active"},
                "VpcPeeringConnectionId": "pcx-2b2b2b2b",
            },
        ]
    },
    {
        "VpcPeeringConnections": [
            {
                "AccepterVpcInfo": {"OwnerId": "999888777666", "VpcId": "vpc-c3c3c3c3"},
                "RequesterVpcInfo": {"OwnerId": "466455466455", "VpcId": "vpc-d4d4d4d4"},
                "Status": {"Code": "expired", "Message": "Expired"},
                "VpcPeeringConnectionId": "pcx-d8d8d8d8",
            },
        ]
    },
]
EXPECTED_VPC_PEERING_CONNECTIONS = [
    vpc_peering_connection(
        id="pcx-1a1a1a1a",
        accepter_owner_id="222333444555",
        accepter_vpc_id="vpc-a1b2c3d4",
        requester_owner_id="121212121212",
        requester_vpc_id="vpc-48d45821",
        status="active",
    ),
    vpc_peering_connection(
        id="pcx-2b2b2b2b",
        accepter_owner_id="787878787878",
        accepter_vpc_id="vpc-f1f1f1f1f1f1f1f1f",
        requester_owner_id="33566455788",
        requester_vpc_id="vpc-c9d8e7f4",
        status="active",
    ),
    vpc_peering_connection(
        id="pcx-d8d8d8d8",
        accepter_owner_id="999888777666",
        accepter_vpc_id="vpc-c3c3c3c3",
        requester_owner_id="466455466455",
        requester_vpc_id="vpc-d4d4d4d4",
        status="expired",
    ),
]

DESCRIBE_IMAGE_1234 = {"Images": [{"CreationDate": "2022-02-21T14:05:14.000Z", "ImageId": "ami-1234", "Public": False}]}
DESCRIBE_IMAGE_5678 = {"Images": [{"CreationDate": "2022-02-21T14:05:14.000Z", "ImageId": "ami-5678", "Public": True}]}

DESCRIBE_INSTANCES = [
    {
        "Reservations": [
            {
                "Instances": [
                    {
                        "ImageId": "ami-1234",
                        "InstanceId": "i-a1b2c3",
                        "LaunchTime": datetime.datetime(2022, 5, 18, 15, 18, 7),
                        "Tags": [{"Key": "Name", "Value": "some-component"}],
                        "MetadataOptions": {"HttpTokens": "required"},
                    }
                ]
            }
        ]
    },
    {
        "Reservations": [
            {
                "Instances": [
                    {
                        "ImageId": "ami-5678",
                        "InstanceId": "i-d4e5f6",
                        "LaunchTime": datetime.datetime(2022, 5, 19, 15, 18, 7),
                        "MetadataOptions": {"HttpTokens": "optional"},
                    }
                ]
            }
        ]
    },
]

EXPECTED_INSTANCES = [
    instance(
        id="i-a1b2c3",
        component="some-component",
        image_id="ami-1234",
        image_creation_date=datetime.datetime(2022, 2, 21, 14, 5, 14, tzinfo=datetime.timezone.utc),
        launch_time=datetime.datetime(2022, 5, 18, 15, 18, 7),
        metadata_options_http_tokens="required",
    ),
    instance(
        id="i-d4e5f6",
        component="Unknown",
        image_id="ami-5678",
        image_creation_date=datetime.datetime(2022, 2, 21, 14, 5, 14, tzinfo=datetime.timezone.utc),
        launch_time=datetime.datetime(2022, 5, 19, 15, 18, 7),
        metadata_options_http_tokens="optional",
    ),
]
