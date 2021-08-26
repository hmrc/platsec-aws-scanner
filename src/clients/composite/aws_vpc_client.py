from logging import getLogger
from random import randint
from typing import AbstractSet, Any, Callable, Dict, List, Optional, Sequence

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_ec2_actions import CreateFlowLogAction, DeleteFlowLogAction, EC2Action
from src.data.aws_ec2_types import FlowLog, Vpc
from src.data.aws_iam_types import Role
from src.data.aws_logs_types import LogGroup, SubscriptionFilter


class AwsVpcClient:
    def __init__(self, ec2: AwsEC2Client, iam: AwsIamClient, logs: AwsLogsClient):
        self._logger = getLogger(self.__class__.__name__)
        self.ec2 = ec2
        self.iam = iam
        self.logs = logs
        self.config = Config()

    def list_vpcs(self) -> List[Vpc]:
        return [self._enrich_vpc(vpc) for vpc in self.ec2.list_vpcs()]

    def _enrich_vpc(self, vpc: Vpc) -> Vpc:
        vpc.flow_logs = [self._enrich_flow_log(fl) for fl in vpc.flow_logs]
        return vpc

    def _enrich_flow_log(self, fl: FlowLog) -> FlowLog:
        fl.deliver_log_role = self.iam.get_role_by_arn(fl.deliver_log_role_arn) if fl.deliver_log_role_arn else None
        fl.log_group = self.logs.describe_log_groups(fl.log_group_name)[0] if fl.log_group_name else None
        return fl

    def find_flow_log_delivery_role(self) -> Role:
        return self.iam.get_role(self.config.logs_vpc_log_group_delivery_role())

    def is_flow_log_role_compliant(self, role: Optional[Role]) -> bool:
        return bool(
            role
            and role.assume_policy == self.config.logs_vpc_log_group_delivery_role_assume_policy()
            and [p.document for p in role.policies] == [self.config.logs_vpc_log_group_delivery_role_policy_document()]
        )

    def is_flow_log_centralised(self, flow_log: FlowLog) -> bool:
        return flow_log.log_group_name == self.config.ec2_flow_log_group_name()

    def is_flow_log_misconfigured(self, flow_log: FlowLog) -> bool:
        return self.is_flow_log_centralised(flow_log) and (
            flow_log.status != self.config.ec2_flow_log_status()
            or flow_log.traffic_type != self.config.ec2_flow_log_traffic_type()
            or flow_log.log_format != self.config.ec2_flow_log_format()
            or not self.is_flow_log_role_compliant(flow_log.deliver_log_role)
        )

    def enforcement_actions(self, vpc: Vpc) -> AbstractSet[EC2Action]:
        return (
            {DeleteFlowLogAction(flow_log.id) for flow_log in self._misconfigured(vpc.flow_logs)}
            .union({DeleteFlowLogAction(flow_log.id) for flow_log in self._centralised(vpc.flow_logs)[1:]})
            .union({CreateFlowLogAction(vpc.id)} if not self._centralised(vpc.flow_logs) else set())  # type: ignore
        )

    def _centralised(self, flow_logs: List[FlowLog]) -> List[FlowLog]:
        return list(
            filter(lambda fl: self.is_flow_log_centralised(fl) and not self.is_flow_log_misconfigured(fl), flow_logs)
        )

    def _misconfigured(self, flow_logs: List[FlowLog]) -> List[FlowLog]:
        return list(filter(lambda fl: self.is_flow_log_misconfigured(fl), flow_logs))

    def is_central_vpc_log_group(self, log_group: LogGroup) -> bool:
        return log_group.name.startswith(self.config.logs_vpc_log_group_prefix()) and bool(
            log_group.subscription_filters
            and [sf for sf in log_group.subscription_filters if self.is_central_vpc_destination_filter(sf)]
        )

    def is_central_vpc_destination_filter(self, sub_filter: SubscriptionFilter) -> bool:
        return (
            sub_filter.filter_pattern == self.config.logs_vpc_log_group_pattern()
            and sub_filter.destination_arn == self.config.logs_vpc_log_group_destination()
        )

    def provide_central_vpc_log_group(self) -> LogGroup:
        return self._find_central_vpc_log_group() or self._create_central_vpc_log_group()

    def _find_central_vpc_log_group(self) -> Optional[LogGroup]:
        central_log_groups = filter(
            lambda lg: self.is_central_vpc_log_group(lg),
            self.logs.describe_log_groups(self.config.logs_vpc_log_group_prefix()),
        )
        return next(central_log_groups, None)

    def _create_central_vpc_log_group(self) -> LogGroup:
        name = f"{self.config.logs_vpc_log_group_prefix()}_{''.join([str(randint(0, 9)) for _ in range(4)])}"
        subscription_filter = SubscriptionFilter(
            log_group_name=name,
            filter_name=f"filter_{name}",
            filter_pattern=self.config.logs_vpc_log_group_pattern(),
            destination_arn=self.config.logs_vpc_log_group_destination(),
        )
        log_group = LogGroup(name=name, subscription_filters=[subscription_filter])
        self._logger.debug(f"creating log group {name}")
        self.logs.create_log_group(name=log_group.name)
        self._logger.debug(f"creating subscription filter {subscription_filter}")
        self.logs.put_subscription_filter(subscription_filter=subscription_filter)
        return log_group

    def apply(self, actions: Sequence[EC2Action]) -> Sequence[EC2Action]:
        action_map: Dict[Any, Callable[[Any], bool]] = {
            CreateFlowLogAction: lambda a: self.ec2.create_flow_logs(a.vpc_id),
            DeleteFlowLogAction: lambda a: self.ec2.delete_flow_logs(a.flow_log_id),
        }
        return [action.update_status("applied" if action_map[type(action)](action) else "failed") for action in actions]
