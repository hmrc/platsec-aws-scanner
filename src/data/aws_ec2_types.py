from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.data.aws_iam_types import Role
from src.data.aws_logs_types import LogGroup
from src.data.aws_organizations_types import Account


@dataclass
class Vpc:
    id: str
    flow_logs: List[FlowLog]

    def __init__(self, id: str, flow_logs: Optional[List[FlowLog]] = None):
        self.id = id
        self.flow_logs = flow_logs or []


def to_vpc(vpc: Dict[Any, Any]) -> Vpc:
    return Vpc(id=vpc["VpcId"])


@dataclass
class FlowLog:
    id: str
    status: str
    log_destination: Optional[str]
    log_destination_type: Optional[str]
    log_group_name: Optional[str]
    traffic_type: str
    log_format: str
    deliver_log_role_arn: Optional[str]
    deliver_log_role: Optional[Role] = None
    log_group: Optional[LogGroup] = None


def to_flow_log(flow_log: Dict[Any, Any]) -> FlowLog:
    return FlowLog(
        id=flow_log["FlowLogId"],
        status=flow_log["FlowLogStatus"],
        log_destination=flow_log.get("LogDestination"),
        log_destination_type=flow_log.get("LogDestinationType"),
        log_group_name=flow_log.get("LogGroupName"),
        traffic_type=flow_log["TrafficType"],
        log_format=flow_log["LogFormat"],
        deliver_log_role_arn=flow_log.get("DeliverLogsPermissionArn"),
    )


@dataclass
class VpcPeeringConnection:
    id: str
    accepter_owner_id: str
    accepter_vpc_id: str
    requester_owner_id: str
    requester_vpc_id: str
    status: str
    accepter: Optional[Account] = None
    requester: Optional[Account] = None


def to_vpc_peering_connection(pcx: Dict[str, Any]) -> VpcPeeringConnection:
    return VpcPeeringConnection(
        id=pcx["VpcPeeringConnectionId"],
        accepter_owner_id=pcx["AccepterVpcInfo"]["OwnerId"],
        accepter_vpc_id=pcx["AccepterVpcInfo"]["VpcId"],
        requester_owner_id=pcx["RequesterVpcInfo"]["OwnerId"],
        requester_vpc_id=pcx["RequesterVpcInfo"]["VpcId"],
        status=pcx["Status"]["Code"],
    )


@dataclass
class Instance:
    id: str
    component: str
    image_id: str
    image_creation_date: Optional[str]
    launch_time: str
    metadata_options_http_tokens: str

    def with_image_creation_date(self, creation_date: str) -> Instance:
        self.image_creation_date = creation_date
        return self


def to_instance(instance: Dict[Any, Any]) -> Instance:
    return Instance(
        id=instance["InstanceId"],
        component="Unknown" if "Tags" not in instance else _find_tag("Name", instance["Tags"]),
        image_id=instance["ImageId"],
        image_creation_date=None,
        launch_time=instance["LaunchTime"],
        metadata_options_http_tokens=instance["MetadataOptions"]["HttpTokens"],
    )


def _find_tag(tag_name: str, tags: List[Dict[str, Any]]) -> str:
    return next(filter(lambda t: t["Key"] == tag_name, tags), {"Value": "Unknown"})["Value"]
