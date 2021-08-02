from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class Vpc:
    id: str


def to_vpc(vpc: Dict[Any, Any]) -> Vpc:
    return Vpc(id=vpc["VpcId"])


@dataclass
class FlowLog:
    id: str
    status: str
    traffic_type: str
    log_destination: str
    log_format: str


def to_flow_log(flow_log: Dict[Any, Any]) -> FlowLog:
    return FlowLog(
        id=flow_log["FlowLogId"],
        status=flow_log["FlowLogStatus"],
        traffic_type=flow_log["TrafficType"],
        log_destination=flow_log["LogDestination"],
        log_format=flow_log["LogFormat"],
    )
