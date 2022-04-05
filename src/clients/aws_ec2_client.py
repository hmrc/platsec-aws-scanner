from logging import getLogger
from typing import Any, Dict, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try
from src.data.aws_ec2_types import (
    FlowLog,
    Instance,
    Vpc,
    VpcPeeringConnection,
    to_flow_log,
    to_instance,
    to_vpc,
    to_vpc_peering_connection,
)
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
                        {"ResourceType": "vpc-flow-log", "Tags": [tag.to_dict() for tag in PLATSEC_SCANNER_TAGS]}
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

    def describe_vpc_peering_connections(self) -> List[VpcPeeringConnection]:
        try:
            paginator = self._ec2.get_paginator("describe_vpc_peering_connections")
            return [to_vpc_peering_connection(pcx) for p in paginator.paginate() for pcx in p["VpcPeeringConnections"]]
        except (BotoCoreError, ClientError) as err:
            raise EC2Exception(f"unable to describe VPC peering connections: {err}")

    def list_instances(self) -> List[Instance]:
        return [
            instance.with_image_creation_date(
                self._get_image_metadata(self._describe_images(instance.image_id), "CreationDate")
            )
            for instance in self._describe_instances()
        ]

    def _describe_instances(self) -> List[Instance]:
        return boto_try(
            lambda: [
                to_instance(instance)
                for page in self._ec2.get_paginator("describe_instances").paginate()
                for reservation in page["Reservations"]
                for instance in reservation["Instances"]
            ],
            list,
            "unable to describe EC2 instances",
        )

    def _describe_images(self, image_id: str) -> List[Dict[str, Any]]:
        return boto_try(
            lambda: list(self._ec2.describe_images(ImageIds=[image_id])["Images"]),
            list,
            f"unable to fetch metadata for image with id {image_id}",
        )

    @staticmethod
    def _get_image_metadata(images: List[Dict[str, Any]], metadata_key: str) -> str:
        return next(iter(images), {metadata_key: "unknown"})[metadata_key]
