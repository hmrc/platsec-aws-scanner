from itertools import chain
from logging import getLogger
from typing import Sequence, List, Any

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import (
    ComplianceAction,
    CreateFlowLogAction,
    DeleteFlowLogAction,
)
from src.data.aws_ec2_types import FlowLog, Vpc


class AwsVpcClient:
    def __init__(self, ec2: AwsEC2Client, iam: AwsIamClient, logs: AwsLogsClient, kms: AwsKmsClient):
        self._logger = getLogger(self.__class__.__name__)
        self.ec2 = ec2
        self.iam = iam
        self.logs = logs
        self.kms = kms
        self.config = Config()

    def list_vpcs(self) -> Sequence[Vpc]:
        return self.ec2.list_vpcs()

    def _is_flow_log_centralised(self, flow_log: FlowLog) -> bool:
        return flow_log.log_destination == self.config.logs_vpc_log_bucket_arn()

    def _is_flow_log_misconfigured(self, flow_log: FlowLog) -> bool:
        return self._is_flow_log_centralised(flow_log) and (
            flow_log.status != self.config.ec2_flow_log_status()
            or flow_log.traffic_type != self.config.ec2_flow_log_traffic_type()
            or flow_log.log_format != self.config.ec2_flow_log_format()
            or flow_log.log_destination_type != self.config.ec2_flow_log_destination_type()
        )

    def enforcement_actions(self, vpcs: Sequence[Vpc]) -> Sequence[ComplianceAction]:
        return [action for vpc in vpcs for action in self._vpc_enforcement_actions(vpc)]

    def _vpc_enforcement_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return list(
            chain(
                self._delete_misconfigured_flow_log_actions(vpc),
                self._delete_redundant_flow_log_actions(vpc),
                self._create_flow_log_actions(vpc),
            )
        )

    def _delete_misconfigured_flow_log_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return [
            DeleteFlowLogAction(ec2_client=self.ec2, flow_log_id=flow_log.id)
            for flow_log in self._find_misconfigured_flow_logs(vpc.flow_logs)
        ]

    def _find_misconfigured_flow_logs(self, flow_logs: Sequence[FlowLog]) -> Sequence[FlowLog]:
        return list(filter(lambda fl: self._is_flow_log_misconfigured(fl), flow_logs))

    def _delete_redundant_flow_log_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return [
            DeleteFlowLogAction(ec2_client=self.ec2, flow_log_id=flow_log.id)
            for flow_log in self._centralised(vpc.flow_logs)[1:]
        ]

    def _create_flow_log_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return (
            [
                CreateFlowLogAction(
                    ec2_client=self.ec2,
                    iam=self.iam,
                    config=self.config,
                    vpc_id=vpc.id,
                )
            ]
            if not self._centralised(vpc.flow_logs)
            else []
        )

    def _centralised(self, fls: Sequence[FlowLog]) -> Sequence[FlowLog]:
        return list(
            filter(lambda fl: self._is_flow_log_centralised(fl) and not self._is_flow_log_misconfigured(fl), fls)
        )
