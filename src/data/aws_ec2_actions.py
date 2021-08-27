from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from src.clients.aws_ec2_client import AwsEC2Client


class EC2Action(ABC):
    description: str
    status: str

    def __init__(self, description: str):
        self.description = description
        self.status = "not applied"

    def update_status(self, s: str) -> EC2Action:
        self.status = s
        return self

    def apply(self, client: Any) -> EC2Action:
        return self.update_status("applied" if self._apply(client) else "failed")

    @abstractmethod
    def _apply(self, client: Any) -> bool:
        """
        :param client: an AWS client
        :return: True if the action succeeded, False otherwise
        """


@dataclass(unsafe_hash=True)
class DeleteFlowLogAction(EC2Action):
    flow_log_id: str

    def __init__(self, flow_log_id: str):
        super().__init__(description="Delete VPC flow log")
        self.flow_log_id = flow_log_id

    def _apply(self, client: AwsEC2Client) -> bool:
        return client.delete_flow_logs(self.flow_log_id)


@dataclass(unsafe_hash=True)
class CreateFlowLogAction(EC2Action):
    vpc_id: str

    def __init__(self, vpc_id: str):
        super().__init__(description="Create centralised VPC flow log")
        self.vpc_id = vpc_id

    def _apply(self, client: AwsEC2Client) -> bool:
        return client.create_flow_logs(self.vpc_id)
