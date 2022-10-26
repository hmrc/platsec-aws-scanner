from itertools import chain
from logging import getLogger
from typing import List, Optional, Sequence

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config, LogGroupConfig
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.aws_log_group_client import AwsLogGroupClient
from src.clients.aws_resolver_client import AwsResolverClient
from src.data.aws_compliance_actions import (
    AssociateResolverQueryLogConfig,
    ComplianceAction,
    CreateFlowLogAction,
    CreateFlowLogDeliveryRoleAction,
    DeleteFlowLogAction,
    DeleteFlowLogDeliveryRoleAction,
    DeleteResolverQueryLogConfig,
    DisassociateResolverQueryLogConfig,
    TagFlowLogDeliveryRoleAction,
    CreateResolverQueryLogConfig,
)
from src.data.aws_ec2_types import FlowLog, Vpc
from src.data.aws_iam_types import Role


class AwsVpcClient:
    def __init__(
        self,
        ec2: AwsEC2Client,
        iam: AwsIamClient,
        logs: AwsLogsClient,
        config: Config,
        log_group: AwsLogGroupClient,
        resolver: AwsResolverClient,
    ):
        self._logger = getLogger(self.__class__.__name__)
        self.ec2 = ec2
        self.iam = iam
        self.logs = logs
        self.config = config
        self.log_group = log_group
        self.resolver = resolver

    def list_vpcs(self) -> Sequence[Vpc]:
        return [self._enrich_vpc(vpc) for vpc in self.ec2.list_vpcs()]

    def _enrich_vpc(self, vpc: Vpc) -> Vpc:
        vpc.flow_logs = [self._enrich_flow_log(fl) for fl in vpc.flow_logs]
        return vpc

    def _enrich_flow_log(self, fl: FlowLog) -> FlowLog:
        fl.deliver_log_role = self.iam.find_role_by_arn(fl.deliver_log_role_arn) if fl.deliver_log_role_arn else None
        fl.log_group = self.logs.find_log_group(fl.log_group_name) if fl.log_group_name else None
        return fl

    def _find_flow_log_delivery_role(self) -> Optional[Role]:
        return self.iam.find_role(self.config.logs_vpc_log_group_delivery_role())

    def _is_flow_log_role_compliant(self, role: Optional[Role]) -> bool:
        return bool(
            role
            and role.assume_policy == self.config.logs_vpc_log_group_delivery_role_assume_policy()
            and role.policies
            and all(p.doc_equals(self.config.logs_vpc_log_group_delivery_role_policy_document()) for p in role.policies)
        )

    def _is_flow_log_centralised(self, flow_log: FlowLog) -> bool:
        return flow_log.log_group_name == self.config.logs_vpc_flow_log_group_config().logs_group_name

    def _is_flow_log_misconfigured(self, flow_log: FlowLog) -> bool:
        return self._is_flow_log_centralised(flow_log) and (
            flow_log.status != self.config.ec2_flow_log_status()
            or flow_log.traffic_type != self.config.ec2_flow_log_traffic_type()
            or flow_log.log_format != self.config.ec2_flow_log_format()
            or flow_log.deliver_log_role_arn is None
            or not flow_log.deliver_log_role_arn.endswith(f":role/{self.config.logs_vpc_log_group_delivery_role()}")
        )

    def enforcement_flow_log_actions(
        self, vpcs: Sequence[Vpc], with_subscription_filter: bool, skip_tags: bool
    ) -> Sequence[ComplianceAction]:
        if not vpcs:
            return list()
        log_group_config = self.config.logs_vpc_flow_log_group_config()
        log_group_actions = self.log_group.log_group_enforcement_actions(
            log_group_config=log_group_config, with_subscription_filter=with_subscription_filter, skip_tags=skip_tags
        )
        delivery_role_actions = self._delivery_role_enforcement_actions(skip_tags)
        vpc_actions = [action for vpc in vpcs for action in self._vpc_flow_enforcement_actions(vpc)]
        return list(chain(log_group_actions, delivery_role_actions, vpc_actions))

    def enforcement_dns_log_actions(
        self, vpcs: Sequence[Vpc], with_subscription_filter: bool, skip_tags: bool
    ) -> Sequence[ComplianceAction]:
        if not vpcs:
            return []

        log_group_config = self.config.logs_vpc_dns_log_group_config()
        log_group_actions = self.log_group.log_group_enforcement_actions(
            log_group_config=log_group_config, with_subscription_filter=with_subscription_filter, skip_tags=skip_tags
        )

        resolver_config = self._resolver_query_log_config_enforcement_actions(
            log_group_config=log_group_config, vpcs=vpcs
        )

        return list(chain(log_group_actions, resolver_config))

    def _resolver_query_log_config_enforcement_actions(
        self, log_group_config: LogGroupConfig, vpcs: Sequence[Vpc]
    ) -> Sequence[ComplianceAction]:
        actions: List[ComplianceAction] = []
        association_actions: List[ComplianceAction] = []
        log_config_name: str = self.config.resolver_dns_query_log_config_name()
        resolver_query_log = next(
            iter(self.resolver.list_resolver_query_log_configs(query_log_config_name=log_config_name)), None
        )

        if resolver_query_log:
            log_group = self.logs.find_log_group(log_group_config.logs_group_name)
            if log_group and resolver_query_log.destination_arn in log_group.arn:  # type: ignore
                new_vpcs = []
                for vpc in vpcs:
                    if not self.resolver.query_log_config_association_exists(
                        vpc_id=vpc.id, resolver_query_log_config_id=resolver_query_log.id
                    ):
                        new_vpcs.append(vpc)
                if new_vpcs:
                    association_actions = self._vpc_log_config_association(
                        vpcs=new_vpcs, log_config_name=log_config_name
                    )

            else:
                for vpc in vpcs:
                    actions.append(DisassociateResolverQueryLogConfig(resolver=self.resolver, resource_id=vpc.id))
                actions.append(
                    DeleteResolverQueryLogConfig(resolver=self.resolver, query_log_config_id=resolver_query_log.id)
                )
                actions.append(
                    CreateResolverQueryLogConfig(
                        logs=self.logs,
                        log_group_config=log_group_config,
                        resolver=self.resolver,
                        query_log_config_name=log_config_name,
                    )
                )
                association_actions = self._vpc_log_config_association(vpcs=vpcs, log_config_name=log_config_name)
        else:

            actions.append(
                CreateResolverQueryLogConfig(
                    logs=self.logs,
                    log_group_config=log_group_config,
                    resolver=self.resolver,
                    query_log_config_name=log_config_name,
                )
            )
            association_actions = self._vpc_log_config_association(vpcs=vpcs, log_config_name=log_config_name)

        return actions + association_actions

    def _vpc_log_config_association(self, vpcs: Sequence[Vpc], log_config_name: str) -> List[ComplianceAction]:
        actions: List[ComplianceAction] = []
        for vpc in vpcs:
            actions.append(DisassociateResolverQueryLogConfig(resolver=self.resolver, resource_id=vpc.id))

        actions.append(
            AssociateResolverQueryLogConfig(resolver=self.resolver, log_config_name=log_config_name, vpcs=vpcs)
        )
        return actions

    def _vpc_flow_enforcement_actions(self, vpc: Vpc) -> Sequence[ComplianceAction]:
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
        log_group_config = self.config.logs_vpc_flow_log_group_config()
        return (
            [
                CreateFlowLogAction(
                    ec2_client=self.ec2,
                    iam=self.iam,
                    log_group_config=log_group_config,
                    vpc_id=vpc.id,
                    config=self.config,
                )
            ]
            if not self._centralised(vpc.flow_logs)
            else []
        )

    def _delivery_role_enforcement_actions(self, skip_tags: bool) -> Sequence[ComplianceAction]:
        recreate_role_actions = list(chain(self._delete_delivery_role_action(), self._create_delivery_role_action()))
        return recreate_role_actions or (self._tag_delivery_role_action(skip_tags))

    def _delete_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_flow_log_delivery_role()
        return (
            [DeleteFlowLogDeliveryRoleAction(iam=self.iam)]
            if (delivery_role and not self._is_flow_log_role_compliant(delivery_role))
            or (not delivery_role and self._delivery_role_policy_exists())
            else []
        )

    def _create_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_flow_log_delivery_role()
        return (
            [CreateFlowLogDeliveryRoleAction(iam=self.iam), TagFlowLogDeliveryRoleAction(self.iam)]
            if not self._is_flow_log_role_compliant(delivery_role)
            else []
        )

    def _tag_delivery_role_action(self, skip_tags: bool) -> Sequence[ComplianceAction]:
        if not skip_tags:
            delivery_role = self._find_flow_log_delivery_role()
            if delivery_role and not set(PLATSEC_SCANNER_TAGS).issubset(delivery_role.tags):
                return [TagFlowLogDeliveryRoleAction(iam=self.iam)]
        return []

    def _delivery_role_policy_exists(self) -> bool:
        return bool(self.iam.find_policy_arn(self.config.logs_vpc_log_group_delivery_role_policy()))

    def _centralised(self, fls: Sequence[FlowLog]) -> Sequence[FlowLog]:
        return list(
            filter(lambda fl: self._is_flow_log_centralised(fl) and not self._is_flow_log_misconfigured(fl), fls)
        )
