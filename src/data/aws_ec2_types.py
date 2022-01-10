from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.data.aws_iam_types import Role
from src.data.aws_logs_types import LogGroup


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
