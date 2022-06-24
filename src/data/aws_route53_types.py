from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.data.aws_iam_types import Role
from src.data.aws_logs_types import LogGroup
from src.data.aws_organizations_types import Account


@dataclass
class Route53_Zone:
    id: str
    name: str
    PrivateZone: str
    query_logs: List[QueryLog]

    def __init__(self, id: str, name: str, PrivateZone: str, query_logs: Optional[List[QueryLog]] = None):
        self.id = id
        self.name = name
        self.PrivateZone = PrivateZone
        self.query_logs = query_logs or []



@dataclass
class QueryLog:
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


def to_query_log(query_log: Dict[Any, Any]) -> QueryLog:
    return QueryLog(
        id=query_log["QueryLogId"],
        status=query_log["QueryLogStatus"],
        log_destination=query_log.get("LogDestination"),
        log_destination_type=query_log.get("LogDestinationType"),
        log_group_name=query_log.get("LogGroupName"),
        traffic_type=query_log["TrafficType"],
        log_format=query_log["LogFormat"],
        deliver_log_role_arn=query_log.get("DeliverLogsPermissionArn"),
    )