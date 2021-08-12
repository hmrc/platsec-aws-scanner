from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.aws_scanner_config import AwsScannerConfig as Config


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
    log_group_name: Optional[str]
    traffic_type: str
    log_format: str

    @property
    def compliance(self) -> FlowLogCompliance:
        return to_flow_log_compliance(self)


def to_flow_log(flow_log: Dict[Any, Any]) -> FlowLog:
    return FlowLog(
        id=flow_log["FlowLogId"],
        status=flow_log["FlowLogStatus"],
        log_group_name=flow_log.get("LogGroupName"),
        traffic_type=flow_log["TrafficType"],
        log_format=flow_log["LogFormat"],
    )


@dataclass
class FlowLogCompliance:
    centralised: bool
    misconfigured: bool


def to_flow_log_compliance(flow_log: FlowLog) -> FlowLogCompliance:
    config = Config()
    centralised = flow_log.log_group_name == config.ec2_flow_log_group_name()
    misconfigured = centralised and (
        flow_log.status != config.ec2_flow_log_status()
        or flow_log.traffic_type != config.ec2_flow_log_traffic_type()
        or flow_log.log_format != config.ec2_flow_log_format()
    )
    return FlowLogCompliance(centralised=centralised, misconfigured=misconfigured)
