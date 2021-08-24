from __future__ import annotations
from dataclasses import dataclass


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
