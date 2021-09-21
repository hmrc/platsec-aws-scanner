from itertools import chain
from logging import getLogger
from typing import Optional, Sequence

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import (
    ComplianceAction,
    CreateVpcLogGroupAction,
    CreateFlowLogAction,
    CreateFlowLogDeliveryRoleAction,
    DeleteFlowLogAction,
    DeleteFlowLogDeliveryRoleAction,
    PutVpcLogGroupSubscriptionFilterAction,
    CreateLogGroupKmsKeyAction,
    DeleteLogGroupKmsKeyAliasAction,
)
from src.data.aws_ec2_types import FlowLog, Vpc
from src.data.aws_iam_types import Role
from src.data.aws_kms_types import Key
from src.data.aws_logs_types import LogGroup, SubscriptionFilter


class AwsVpcClient:
    def __init__(self, ec2: AwsEC2Client, iam: AwsIamClient, logs: AwsLogsClient, kms: AwsKmsClient):
        self._logger = getLogger(self.__class__.__name__)
        self.ec2 = ec2
        self.iam = iam
        self.logs = logs
        self.kms = kms
        self.config = Config()

    def list_vpcs(self) -> Sequence[Vpc]:
        return [self._enrich_vpc(vpc) for vpc in self.ec2.list_vpcs()]

    def _enrich_vpc(self, vpc: Vpc) -> Vpc:
        vpc.flow_logs = [self._enrich_flow_log(fl) for fl in vpc.flow_logs]
        return vpc

    def _enrich_flow_log(self, fl: FlowLog) -> FlowLog:
        fl.deliver_log_role = self.iam.find_role_by_arn(fl.deliver_log_role_arn) if fl.deliver_log_role_arn else None
        fl.log_group = self._find_log_group(fl.log_group_name) if fl.log_group_name else None
        return fl

    def _find_log_group(self, name: str) -> Optional[LogGroup]:
        log_group = next(iter(self.logs.describe_log_groups(name)), None)
        kms_key = self.kms.get_key(log_group.kms_key_id) if log_group and log_group.kms_key_id else None
        return log_group.with_kms_key(kms_key) if log_group else None

    def _find_flow_log_delivery_role(self) -> Optional[Role]:
        return self.iam.find_role(self.config.logs_vpc_log_group_delivery_role())

    def _get_flow_log_delivery_role_arn(self) -> str:
        return self.iam.get_role(self.config.logs_vpc_log_group_delivery_role()).arn

    def _is_flow_log_role_compliant(self, role: Optional[Role]) -> bool:
        return bool(
            role
            and role.assume_policy == self.config.logs_vpc_log_group_delivery_role_assume_policy()
            and [p.document for p in role.policies] == [self.config.logs_vpc_log_group_delivery_role_policy_document()]
        )

    def _is_flow_log_centralised(self, flow_log: FlowLog) -> bool:
        return flow_log.log_group_name == self.config.logs_vpc_log_group_name()

    def _is_flow_log_misconfigured(self, flow_log: FlowLog) -> bool:
        return self._is_flow_log_centralised(flow_log) and (
            flow_log.status != self.config.ec2_flow_log_status()
            or flow_log.traffic_type != self.config.ec2_flow_log_traffic_type()
            or flow_log.log_format != self.config.ec2_flow_log_format()
            or flow_log.deliver_log_role_arn is None
            or not flow_log.deliver_log_role_arn.endswith(f":role/{self.config.logs_vpc_log_group_delivery_role()}")
        )

    def enforcement_actions(self, vpcs: Sequence[Vpc]) -> Sequence[ComplianceAction]:
        kms_actions = self._kms_enforcement_actions()
        log_group_actions = self._vpc_log_group_enforcement_actions()
        delivery_role_actions = self._delivery_role_enforcement_actions()
        vpc_actions = [action for vpc in vpcs for action in self._vpc_enforcement_actions(vpc)]
        return list(chain(kms_actions, log_group_actions, delivery_role_actions, vpc_actions))

    def _vpc_enforcement_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return list(
            chain(
                self._delete_misconfigured_flow_log_actions(vpc),
                self._delete_redundant_flow_log_actions(vpc),
                self._create_flow_log_actions(vpc),
            )
        )

    def _kms_enforcement_actions(self) -> Sequence[ComplianceAction]:
        alias = self.kms.find_alias(self.config.kms_key_alias())
        key = self.kms.get_key(alias.target_key_id) if alias and alias.target_key_id else None
        return (
            [CreateLogGroupKmsKeyAction()]
            if alias is None
            else [DeleteLogGroupKmsKeyAliasAction(), CreateLogGroupKmsKeyAction()]
            if not self._is_key_compliant(key)
            else []
        )

    def _is_key_compliant(self, key: Optional[Key]) -> bool:
        return key is not None and self._is_key_policy_compliant(key)

    def _is_key_policy_compliant(self, key: Key) -> bool:
        return key.policy is not None and key.policy["Statement"] == self.config.kms_key_policy_statements(
            key.account_id, key.region
        )

    def _delete_misconfigured_flow_log_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return [DeleteFlowLogAction(flow_log.id) for flow_log in self._find_misconfigured_flow_logs(vpc.flow_logs)]

    def _find_misconfigured_flow_logs(self, flow_logs: Sequence[FlowLog]) -> Sequence[FlowLog]:
        return list(filter(lambda fl: self._is_flow_log_misconfigured(fl), flow_logs))

    def _delete_redundant_flow_log_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return [DeleteFlowLogAction(flow_log.id) for flow_log in self._centralised(vpc.flow_logs)[1:]]

    def _create_flow_log_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
        return (
            [CreateFlowLogAction(vpc.id, self.config.logs_vpc_log_group_name(), self._get_flow_log_delivery_role_arn)]
            if not self._centralised(vpc.flow_logs)
            else []
        )

    def _delivery_role_enforcement_actions(self) -> Sequence[ComplianceAction]:
        return list(chain(self._delete_delivery_role_action(), self._create_delivery_role_action()))

    def _delete_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_flow_log_delivery_role()
        return (
            [DeleteFlowLogDeliveryRoleAction()]
            if (delivery_role and not self._is_flow_log_role_compliant(delivery_role))
            or (not delivery_role and self._delivery_role_policy_exists())
            else []
        )

    def _create_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_flow_log_delivery_role()
        return [CreateFlowLogDeliveryRoleAction()] if not self._is_flow_log_role_compliant(delivery_role) else []

    def _delivery_role_policy_exists(self) -> bool:
        return bool(self.iam.find_policy_arn(self.config.logs_vpc_log_group_delivery_role_policy_name()))

    def _vpc_log_group_enforcement_actions(self) -> Sequence[ComplianceAction]:
        lg = self._find_log_group(self.config.logs_vpc_log_group_name())
        return (
            [CreateVpcLogGroupAction(), PutVpcLogGroupSubscriptionFilterAction()]
            if not lg
            else [PutVpcLogGroupSubscriptionFilterAction()]
            if not self._is_central_vpc_log_group(lg)
            else []
        )

    def _centralised(self, fls: Sequence[FlowLog]) -> Sequence[FlowLog]:
        return list(
            filter(lambda fl: self._is_flow_log_centralised(fl) and not self._is_flow_log_misconfigured(fl), fls)
        )

    def _is_central_vpc_log_group(self, log_group: LogGroup) -> bool:
        return log_group.name == self.config.logs_vpc_log_group_name() and any(
            map(self._is_central_vpc_destination_filter, log_group.subscription_filters)
        )

    def _is_central_vpc_destination_filter(self, sub_filter: SubscriptionFilter) -> bool:
        return (
            sub_filter.filter_pattern == self.config.logs_vpc_log_group_pattern()
            and sub_filter.destination_arn == self.config.logs_vpc_log_group_destination()
        )

    def apply(self, actions: Sequence[ComplianceAction]) -> Sequence[ComplianceAction]:
        client_map = {
            CreateLogGroupKmsKeyAction: self.kms,
            DeleteLogGroupKmsKeyAliasAction: self.kms,
            CreateVpcLogGroupAction: self.logs,
            CreateFlowLogAction: self.ec2,
            CreateFlowLogDeliveryRoleAction: self.iam,
            DeleteFlowLogAction: self.ec2,
            DeleteFlowLogDeliveryRoleAction: self.iam,
            PutVpcLogGroupSubscriptionFilterAction: self.logs,
        }
        return [a.apply(client) for a in actions for typ, client in client_map.items() if isinstance(a, typ)]
