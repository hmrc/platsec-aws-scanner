from logging import getLogger
from typing import Any, Dict, List, Sequence

from botocore.client import BaseClient

from src.clients import boto_try
from src.data.aws_ec2_types import FlowLog, Vpc, to_flow_log, to_vpc
from src.data.aws_ec2_actions import CreateFlowLogAction, EC2Action, DeleteFlowLogAction
from src.data.aws_scanner_exceptions import UnsupportedActionException


class AwsEC2Client:
    def __init__(self, boto_ec2: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._ec2 = boto_ec2
        self._action_map = {
            CreateFlowLogAction: lambda a: self._create_flow_log(a.vpc_id),
            DeleteFlowLogAction: lambda a: self._delete_flow_log(a.flow_log_id),
        }

    def list_vpcs(self) -> List[Vpc]:
        return [self._enrich_vpc(vpc) for vpc in self._describe_vpcs()]

    def apply(self, actions: Sequence[EC2Action]) -> Sequence[EC2Action]:
        return [self._apply_action(action) for action in actions]

    def _apply_action(self, action: EC2Action) -> EC2Action:
        return action.update_status("applied" if self._action_map[type(action)](action) else "failed")  # type: ignore

    def _create_flow_log(self, vpc_id: str) -> bool:
        raise UnsupportedActionException("create centralised flow log action hasn't been implemented yet")

    def _delete_flow_log(self, flow_log_id: str) -> bool:
        return boto_try(
            lambda: self._is_success(self._ec2.delete_flow_logs(FlowLogIds=[flow_log_id])),
            bool,
            f"unable to delete flow log {flow_log_id}",
        )

    def _enrich_vpc(self, vpc: Vpc) -> Vpc:
        vpc.flow_logs = self._describe_flow_logs(vpc)
        return vpc

    def _describe_vpcs(self) -> List[Vpc]:
        return boto_try(
            lambda: [to_vpc(vpc) for vpc in self._ec2.describe_vpcs()["Vpcs"]], list, "unable to describe VPCs"
        )

    def _describe_flow_logs(self, vpc: Vpc) -> List[FlowLog]:
        filters = [{"Name": "resource-id", "Values": [vpc.id]}]
        return boto_try(
            lambda: [to_flow_log(flow_log) for flow_log in self._ec2.describe_flow_logs(Filters=filters)["FlowLogs"]],
            list,
            f"unable to describe flow logs for {vpc}",
        )

    def _is_success(self, resp: Dict[Any, Any]) -> bool:
        errors = resp["Unsuccessful"]
        if errors:
            self._logger.error(errors)
        return not len(errors)