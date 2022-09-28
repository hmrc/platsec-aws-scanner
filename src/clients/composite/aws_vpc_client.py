from itertools import chain
from logging import getLogger
from typing import Optional, Sequence

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.aws_log_group_client import AwsLogGroupClient
from src.clients.aws_resolver_client import AwsResolverClient
from src.data.aws_compliance_actions import (
    ComplianceAction,
    CreateFlowLogAction,
    CreateFlowLogDeliveryRoleAction,
    DeleteFlowLogAction,
    DeleteFlowLogDeliveryRoleAction,
    TagFlowLogDeliveryRoleAction,
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
        self, vpcs: Sequence[Vpc], with_subscription_filter: bool
    ) -> Sequence[ComplianceAction]:
        if not vpcs:
            return list()
        log_group_config = self.config.logs_vpc_flow_log_group_config()
        log_group_actions = self.log_group.log_group_enforcement_actions(
            log_group_config=log_group_config, with_subscription_filter=with_subscription_filter
        )
        delivery_role_actions = self._delivery_role_enforcement_actions()
        vpc_actions = [action for vpc in vpcs for action in self._vpc_flow_enforcement_actions(vpc)]
        return list(chain(log_group_actions, delivery_role_actions, vpc_actions))

    def enforcement_dns_log_actions(
        self, vpcs: Sequence[Vpc], with_subscription_filter: bool
    ) -> Sequence[ComplianceAction]:

        print("I'm at enforcement_dns_log_actions")
        # if not vpcs:
        return list()

    # not yet tested yet see test_crate_do_nothing_when_all_correct
    # log_group_config=self.config.logs_vpc_dns_log_group_config()
    # log_group_actions = self.log_group.log_group_enforcement_actions(log_group_config=log_group_config,
    # with_subscription_filter=with_subscription_filter)
    # resolver_query_log_config =self.
    # _resolver_query_log_config_enforcement_actions(log_group_config=log_group_config)
    # vpc_actions = [action for vpc in vpcs for action in self.
    # _vpc_resolver_query_log_config_associations_enforcement_actions(vpc=vpc,
    # log_group_config=log_group_config)]
    # return list(chain(log_group_actions, resolver_query_log_config, vpc_actions))

    # def _resolver_query_log_config_enforcement_actions(self,
    # log_group_config: LogGroupConfig) -> Sequence[ComplianceAction]:
    #     return [CreateResolverQueryLogConfig(log=self.logs, log_group_config=log_group_config,
    # resolver=self.resolver)]
    #

    # def _vpc_resolver_query_log_config_associations_enforcement_actions(self, vpc: Vpc,
    # log_group_config: LogGroupConfig) -> Sequence[ComplianceAction]:
    #     return [CreateResolverQueryLogConfigAssociation(log=self.logs, resolver=self.resolver,
    # log_group_config=log_group_config, vpc=vpc)]
    #

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

    def _delivery_role_enforcement_actions(self) -> Sequence[ComplianceAction]:
        recreate_role_actions = list(chain(self._delete_delivery_role_action(), self._create_delivery_role_action()))
        return recreate_role_actions or self._tag_delivery_role_action()

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

    def _tag_delivery_role_action(self) -> Sequence[ComplianceAction]:
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
