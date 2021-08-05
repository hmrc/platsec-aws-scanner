from __future__ import annotations
from dataclasses import dataclass
from typing import AbstractSet, List

from src.data.aws_ec2_types import FlowLog, Vpc


@dataclass
class EC2Action:
    description: str
    status: str

    def __init__(self, description: str):
        self.description = description
        self.status = "not applied"

    def update_status(self, s: str) -> EC2Action:
        self.status = s
        return self


@dataclass(unsafe_hash=True)
class DeleteFlowLogAction(EC2Action):
    flow_log_id: str

    def __init__(self, flow_log_id: str):
        super().__init__(description="Delete VPC flow log")
        self.flow_log_id = flow_log_id


@dataclass(unsafe_hash=True)
class CreateFlowLogAction(EC2Action):
    vpc_id: str

    def __init__(self, vpc_id: str):
        super().__init__(description="Create centralised VPC flow log")
        self.vpc_id = vpc_id


def enforcement_actions(vpc: Vpc) -> AbstractSet[EC2Action]:
    return (
        {DeleteFlowLogAction(flow_log.id) for flow_log in _misconfigured(vpc.flow_logs)}
        .union({DeleteFlowLogAction(flow_log.id) for flow_log in _centralised(vpc.flow_logs)[1:]})
        .union({CreateFlowLogAction(vpc.id)} if not _centralised(vpc.flow_logs) else set())  # type: ignore
    )


def _centralised(flow_logs: List[FlowLog]) -> List[FlowLog]:
    return list(filter(lambda fl: fl.compliance.centralised and not fl.compliance.misconfigured, flow_logs))


def _misconfigured(flow_logs: List[FlowLog]) -> List[FlowLog]:
    return list(filter(lambda fl: fl.compliance.misconfigured, flow_logs))
