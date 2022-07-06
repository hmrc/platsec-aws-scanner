from logging import getLogger
from typing import Any, Dict, Sequence, List, Optional
from itertools import chain
from src import PLATSEC_SCANNER_TAGS
from src.data.aws_compliance_actions import (
    ComplianceAction
)
from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

import  src.data.aws_route53_types as route53Type
from src.aws_scanner_config import AwsScannerConfig as Config
 
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient

from src.data.aws_compliance_actions import (
    ComplianceAction,
    DeleteRoute53LogGroupSubscriptionFilterAction,
    PutRoute53LogGroupSubscriptionFilterAction,
    PutRoute53LogGroupRetentionPolicyAction,
    TagRoute53LogGroupAction,
    CreateRoute53LogGroupAction,
    DeleteQueryLogAction,
    DeleteQueryLogDeliveryRoleAction,
    CreateQueryLogDeliveryRoleAction,
    TagQueryLogDeliveryRoleAction,
    CreateQueryLogAction
)

from src.data.aws_scanner_exceptions import HostedZonesException, QueryLogException
from src.data.aws_logs_types import LogGroup, SubscriptionFilter


class AwsRoute53Client:
    def __init__(self, boto_route53: BaseClient, iam: AwsIamClient, logs: AwsLogsClient, kms: AwsKmsClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._route53 = boto_route53
        self._iam = iam
        self._logs = logs
        self.kms = kms
        self.config = Config()

    def list_hosted_zones(self) -> Dict[Any, Any]:
        public_zones: Dict[Any, Any] = {}
        hostedzones = self._route53.list_hosted_zones()["HostedZones"]
        for host in hostedzones:
            zone = route53Type.to_route53Zone(host)
            if not zone.privateZone:
                queryLogConfig = self._route53.list_query_logging_configs(zone.id.replace("/hostedzone/", ""))
                if len(queryLogConfig) > 0 and len(queryLogConfig["QueryLoggingConfigs"]) > 0:
                    zone.queryLog = queryLogConfig["QueryLoggingConfigs"][0]["CloudWatchLogsLogGroupArn"]
                public_zones[zone.id] = zone

        return public_zones
       
   
       

    def list_query_logging_configs(self, id: str) -> Any:
        try:
            return self._route53.list_query_logging_configs(HostedZoneId=id)
        except (BotoCoreError, ClientError) as err:
            raise QueryLogException(f"unable to get the query log config: {err}")

    def create_query_logging_config(self, hosted_zone_id: str, cloudwatch_logs_loggrouparn: str) -> Any:
        return self._route53.create_query_logging_config(
            HostedZoneId=hosted_zone_id, CloudWatchLogsLogGroupArn=cloudwatch_logs_loggrouparn
        )
        
    def enforcement_actions(self, hostedZones: Sequence[route53Type.Route53Zone], with_subscription_filter: bool) -> Sequence[ComplianceAction]:
        if not hostedZones:
            return list()
        log_group_actions = self._route53_log_group_enforcement_actions(with_subscription_filter)
        delivery_role_actions = self._delivery_role_enforcement_actions()
        route53_actions = [action for zone in hostedZones for action in self._route53_enforcement_actions(hostedZones)]
        return list(chain(log_group_actions, delivery_role_actions, route53_actions))


    def _route53_enforcement_actions(self, hostedZones: hostedZones) -> Sequence[ComplianceAction]:
        return list(
            chain(
                # self._delete_misconfigured_query_log_actions(hostedZones),
                # self._delete_redundant_flow_log_actions(hostedZones),
                self._create_query_log_actions(hostedZones),
            )
        )

    def _is_query_log_misconfigured(self, query_log: QueryLog) -> bool:
        return self._is_query_log_centralised(query_log) and (
            query_log.status != self.config.ec2_query_log_status()
            or query_log.traffic_type != self.config.ec2_query_log_traffic_type()
            or query_log.log_format != self.config.ec2_query_log_format()
            or query_log.deliver_log_role_arn is None
            or not query_log.deliver_log_role_arn.endswith(f":role/{self.config.logs_vpc_log_group_delivery_role()}")
        )


    # def _delete_misconfigured_query_log_actions(self, hostedZones: Sequence[route53Type.Route53Zone]) -> Sequence[ComplianceAction]:
    #     return [
    #         for zone in hostedZones:


    #             DeleteQueryLogAction(route53_client=self._route53, query_log_id=query_log.id)
    #             for query_log in self._find_misconfigured_flow_logs(hostedZones.flow_logs)
    #     ]

        
    def _create_query_log_actions(self, hostedZones: Sequence[route53Type.Route53Zone]) -> Sequence[ComplianceAction]:
        queryLogActionList = []
        for zone in hostedZones:
            if zone.queryLog == "":
                 queryLogActionList.append(CreateQueryLogAction(self._route53, self._iam, self._config, zone.id ))
        return  queryLogActionList
        
    def _route53_log_group_enforcement_actions(self, with_subscription_filter: bool) -> Sequence[ComplianceAction]: 
        log_group = self._find_log_group(self.config.logs_route53_log_group_name())
        actions: List[Any] = []
        if log_group:
            if self._is_central_route53_log_group(log_group) and not with_subscription_filter:
                actions.append(DeleteRoute53LogGroupSubscriptionFilterAction(logs=self._logs))
            if not self._is_central_route53_log_group(log_group) and with_subscription_filter:
                actions.append(PutRoute53LogGroupSubscriptionFilterAction(logs=self._logs))
            if log_group.retention_days != self.config.logs_route53_log_group_retention_policy_days():
                actions.append(PutRoute53LogGroupRetentionPolicyAction(logs=self._logs))
            if not set(PLATSEC_SCANNER_TAGS).issubset(log_group.tags):
                actions.append(TagRoute53LogGroupAction(logs=self._logs))
        else:
            actions.extend(
                [
                    CreateRoute53LogGroupAction(logs=self._logs),
                    PutRoute53LogGroupRetentionPolicyAction(logs=self._logs),
                    TagRoute53LogGroupAction(logs=self._logs),
                ]
            )
            if with_subscription_filter:
                actions.append(PutRoute53LogGroupSubscriptionFilterAction(logs=self._logs))

        return actions
    
    def _find_log_group(self, name: str) -> Optional[LogGroup]:
        log_group = next(iter(self._logs.describe_log_groups(name)), None)
        kms_key = self.kms.get_key(log_group.kms_key_id) if log_group and log_group.kms_key_id else None
        return log_group.with_kms_key(kms_key) if log_group else None
    
    def _delivery_role_enforcement_actions(self) -> Sequence[ComplianceAction]:
        recreate_role_actions = list(chain(self._delete_delivery_role_action(), self._create_delivery_role_action()))
        return recreate_role_actions or self._tag_delivery_role_action()
    
    def _is_central_route53_log_group(self, log_group: LogGroup) -> bool:
        return log_group.name == self.config.logs_route53_log_group_name() and any(
            map(self._is_central_route53_destination_filter, log_group.subscription_filters)
        )
        
    def _is_central_route53_destination_filter(self, sub_filter: SubscriptionFilter) -> bool:
        return (
            sub_filter.filter_pattern == self.config.logs_route53_log_group_pattern()
            and sub_filter.destination_arn == self.config.logs_route53_log_group_destination()
        )
        
    def _delete_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_query_log_delivery_role()
        return (
            [DeleteQueryLogDeliveryRoleAction(iam=self._iam)]
            if (delivery_role and not self._is_query_log_role_compliant(delivery_role))
            or (not delivery_role and self._delivery_role_policy_exists())
            else []
        )
    
    def _create_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_query_log_delivery_role()
        return (
            [CreateQueryLogDeliveryRoleAction(iam=self._iam), TagQueryLogDeliveryRoleAction(self._iam)]
            if not self._is_query_log_role_compliant(delivery_role)
            else []
        )
    
    def _tag_delivery_role_action(self) -> Sequence[ComplianceAction]:
        delivery_role = self._find_query_log_delivery_role()
        if delivery_role and not set(PLATSEC_SCANNER_TAGS).issubset(delivery_role.tags):
            return [TagQueryLogDeliveryRoleAction(iam=self._iam)]
        return []

    def _is_query_log_role_compliant(self, role: Optional[Role]) -> bool:
        return bool(
            role
            and role.assume_policy == self.config.logs_route53_log_group_delivery_role_assume_policy()
            and role.policies
            and all(p.doc_equals(self.config.logs_route53_log_group_delivery_role_policy_document()) for p in role.policies)
        )
 
    def _delivery_role_policy_exists(self) -> bool:
        return bool(self._iam.find_policy_arn(self.config.logs_route53_log_group_delivery_role_policy()))
    
    def _find_query_log_delivery_role(self) -> Optional[Role]:
        return self._iam.find_role(self.config.logs_route53_log_group_delivery_role())
    
    def _is_query_log_role_compliant(self, role: Optional[Role]) -> bool:
        return bool(
            role
            and role.assume_policy == self.config.logs_route53_log_group_delivery_role_assume_policy()
            and role.policies
            and all(p.doc_equals(self.config.logs_route53_log_group_delivery_role_policy_document()) for p in role.policies)
        )
        
    def _find_query_log_delivery_role(self) -> Optional[Role]:
        return self._iam.find_role(self.config.logs_route53_log_group_delivery_role())