from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from logging import getLogger
from typing import Any, Callable, Optional

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_scanner_exceptions import AwsScannerException


class ComplianceAction(ABC):
    description: str
    status: Optional[str]

    def __init__(self, description: str):
        self.description = description
        self.status = None

    def update_status(self, s: str) -> ComplianceAction:
        self.status = s
        return self

    def apply(self, client: Any) -> ComplianceAction:
        try:
            self._apply(client)
            return self.update_status("applied")
        except AwsScannerException as ex:
            getLogger(self.__class__.__name__).error(f"{self.description} failed: {ex}")
            return self.update_status(f"failed: {ex}")

    @abstractmethod
    def _apply(self, client: Any) -> None:
        """
        :param client: an AWS client
        :return: True if the action succeeded, False otherwise
        """


@dataclass(unsafe_hash=True)
class DeleteFlowLogAction(ComplianceAction):
    flow_log_id: str

    def __init__(self, flow_log_id: str):
        super().__init__("Delete VPC flow log")
        self.flow_log_id = flow_log_id

    def _apply(self, client: AwsEC2Client) -> None:
        client.delete_flow_logs(self.flow_log_id)


@dataclass(unsafe_hash=True)
class CreateFlowLogAction(ComplianceAction):
    vpc_id: str
    log_group_name: str
    permission_resolver: Callable[[], str] = field(compare=False, hash=False, repr=False)

    def __init__(self, vpc_id: str, log_group_name: str, permission_resolver: Callable[[], str]):
        super().__init__("Create VPC flow log")
        self.vpc_id = vpc_id
        self.log_group_name = log_group_name
        self.permission_resolver = permission_resolver

    def _apply(self, client: AwsEC2Client) -> None:
        client.create_flow_logs(self.vpc_id, self.log_group_name, self.permission_resolver())


@dataclass(unsafe_hash=True)
class CreateFlowLogDeliveryRoleAction(ComplianceAction):
    def __init__(self) -> None:
        super().__init__("Create delivery role for VPC flow log")

    def _apply(self, client: AwsIamClient) -> None:
        config = Config()
        client.attach_role_policy(
            client.create_role(
                config.logs_vpc_log_group_delivery_role(),
                config.logs_vpc_log_group_delivery_role_assume_policy(),
            ),
            client.create_policy(
                config.logs_vpc_log_group_delivery_role_policy_name(),
                config.logs_vpc_log_group_delivery_role_policy_document(),
            ),
        )


@dataclass(unsafe_hash=True)
class DeleteFlowLogDeliveryRoleAction(ComplianceAction):
    def __init__(self) -> None:
        super().__init__("Delete delivery role for VPC flow log")

    def _apply(self, client: AwsIamClient) -> None:
        config = Config()
        client.delete_policy(config.logs_vpc_log_group_delivery_role_policy_name())
        client.delete_role(config.logs_vpc_log_group_delivery_role())


@dataclass(unsafe_hash=True)
class CreateVpcLogGroupAction(ComplianceAction):
    def __init__(self) -> None:
        super().__init__("Create central VPC log group")

    def _apply(self, client: AwsLogsClient) -> None:
        client.create_log_group(Config().logs_vpc_log_group_name())


@dataclass(unsafe_hash=True)
class PutVpcLogGroupSubscriptionFilterAction(ComplianceAction):
    def __init__(self) -> None:
        super().__init__("Put central VPC log group subscription filter")

    def _apply(self, client: AwsLogsClient) -> None:
        config = Config()
        log_group_name = config.logs_vpc_log_group_name()
        client.put_subscription_filter(
            log_group_name=log_group_name,
            filter_name=f"{log_group_name}_sub_filter",
            filter_pattern=config.logs_vpc_log_group_pattern(),
            destination_arn=config.logs_vpc_log_group_destination(),
        )
