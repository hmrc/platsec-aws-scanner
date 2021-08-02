from logging import getLogger
from typing import List

from botocore.client import BaseClient

from src.clients import boto_try
from src.data.aws_ec2_types import FlowLog, Vpc, to_flow_log, to_vpc


class AwsEC2Client:
    def __init__(self, boto_ec2: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._ec2 = boto_ec2

    def describe_vpcs(self) -> List[Vpc]:
        return boto_try(
            lambda: [to_vpc(vpc) for vpc in self._ec2.describe_vpcs()["Vpcs"]], list, "unable to describe VPCs"
        )

    def describe_flow_logs(self, vpc: Vpc) -> List[FlowLog]:
        filters = [{"Name": "resource-id", "Values": [vpc.id]}]
        return boto_try(
            lambda: [to_flow_log(flow_log) for flow_log in self._ec2.describe_flow_logs(Filters=filters)["FlowLogs"]],
            list,
            f"unable to describe flow logs for {vpc}",
        )
