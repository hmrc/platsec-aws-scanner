from dataclasses import dataclass
from typing import FrozenSet, List

from src.data.aws_ec2_types import FlowLog, Vpc


@dataclass
class FlowLogAction:
    pass


@dataclass(unsafe_hash=True)
class DeleteFlowLogAction(FlowLogAction):
    flow_log_id: str


@dataclass(unsafe_hash=True)
class CreateFlowLogAction(FlowLogAction):
    vpc_id: str


def to_flow_log_actions(vpc: Vpc) -> FrozenSet[FlowLogAction]:
    return frozenset(
        {DeleteFlowLogAction(flow_log.id) for flow_log in _misconfigured(vpc.flow_logs)}
        .union({DeleteFlowLogAction(flow_log.id) for flow_log in _centralised(vpc.flow_logs)[1:]})
        .union({CreateFlowLogAction(vpc.id)} if not _centralised(vpc.flow_logs) else set())  # type: ignore
    )


def _centralised(flow_logs: List[FlowLog]) -> List[FlowLog]:
    return list(filter(lambda fl: fl.compliance.centralised and not fl.compliance.misconfigured, flow_logs))


def _misconfigured(flow_logs: List[FlowLog]) -> List[FlowLog]:
    return list(filter(lambda fl: fl.compliance.misconfigured, flow_logs))
