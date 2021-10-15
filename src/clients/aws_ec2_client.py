from logging import getLogger
from typing import Any, Dict, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try
from src.data.aws_ec2_types import FlowLog, Vpc, to_flow_log, to_vpc
from src.data.aws_scanner_exceptions import EC2Exception


class AwsEC2Client:
    def __init__(self, boto_ec2: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._ec2 = boto_ec2

    def list_vpcs(self) -> List[Vpc]:
        return [self._enrich_vpc(vpc) for vpc in self._describe_vpcs()]

    def create_flow_logs(self, vpc_id: str, log_group_name: str, permission: str) -> None:
        self._logger.debug(f"creating flow logs for VPC {vpc_id}")
        try:
            self._is_success(
                "create_flow_logs",
                self._ec2.create_flow_logs(
                    DeliverLogsPermissionArn=permission,
                    LogGroupName=log_group_name,
                    ResourceIds=[vpc_id],
                    ResourceType="VPC",
                    TrafficType="ALL",
                    LogDestinationType="cloud-watch-logs",
                    LogFormat=self._config.ec2_flow_log_format(),
                    TagSpecifications=[
                        {
                            "ResourceType": "vpc-flow-log",
                            "Tags": [dict(Key=tag.key, Value=tag.value) for tag in PLATSEC_SCANNER_TAGS],
                        }
                    ],
                ),
            )
        except (BotoCoreError, ClientError) as err:
            raise EC2Exception(f"unable to create flow logs for VPC {vpc_id}: {err}")

    def delete_flow_logs(self, flow_log_id: str) -> None:
        self._logger.debug(f"deleting flow logs with id {flow_log_id}")
        try:
            self._is_success("delete_flow_logs", self._ec2.delete_flow_logs(FlowLogIds=[flow_log_id]))
        except (BotoCoreError, ClientError) as err:
            raise EC2Exception(f"unable to delete flow logs with id {flow_log_id}: {err}")

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

    @staticmethod
    def _is_success(operation: str, resp: Dict[Any, Any]) -> None:
        errors = resp["Unsuccessful"]
        if errors:
            raise EC2Exception(f"unable to perform {operation}: {errors}")
