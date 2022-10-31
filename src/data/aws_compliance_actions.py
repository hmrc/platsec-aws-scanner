from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass, field
from logging import getLogger, Logger
from typing import Any, Dict, Optional, Sequence

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.aws_scanner_config import LogGroupConfig
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.aws_resolver_client import AwsResolverClient
from src.data.aws_ec2_types import Vpc
from src.data.aws_scanner_exceptions import AwsScannerException, LogsException
from src.clients.aws_hosted_zones_client import AwsHostedZonesClient
from src.data.aws_organizations_types import Account


@dataclass
class ComplianceActionReport:
    description: Optional[str]
    status: Optional[str]
    details: Dict[str, Any]

    def __init__(
        self, status: Optional[str] = None, description: Optional[str] = None, details: Optional[Dict[str, Any]] = None
    ):
        self.status = status
        self.description = description
        self.details = details or dict()

    def applied(self, details: Optional[Dict[str, Any]] = None) -> ComplianceActionReport:
        self.status = "applied"
        self.details |= details or dict()
        return self

    def failed(self, reason: str) -> ComplianceActionReport:
        self.status = f"failed: {reason}"
        return self


class ComplianceAction:
    description: str
    logger: Logger

    def __init__(self, description: str):
        self.description = description
        self.logger = getLogger(self.__class__.__name__)

    def apply(self) -> ComplianceActionReport:
        report = self.plan()
        try:
            return report.applied(details=self._apply())
        except AwsScannerException as ex:
            self.logger.error(f"{self.description} failed: {ex}")
            return report.failed(str(ex))

    @abstractmethod
    def _apply(self) -> Optional[Dict[str, Any]]:
        """"""

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(description=self.description)


@dataclass
class DeleteFlowLogAction(ComplianceAction):
    flow_log_id: str

    def __init__(self, ec2_client: AwsEC2Client, flow_log_id: str):
        super().__init__("Delete VPC flow log")
        self.flow_log_id = flow_log_id
        self.logs = ec2_client

    def _apply(self) -> None:
        self.logs.delete_flow_logs(self.flow_log_id)

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(description=self.description, details=dict(flow_log_id=self.flow_log_id))


@dataclass
class CreateResolverQueryLogConfig(ComplianceAction):
    log_group_config: LogGroupConfig
    log: AwsLogsClient
    resolver: AwsResolverClient
    query_log_config_name: str

    def __init__(
        self,
        logs: AwsLogsClient,
        resolver: AwsResolverClient,
        log_group_config: LogGroupConfig,
        query_log_config_name: str,
    ):
        super().__init__("Create Resolver Query Log Config")
        self.log_group_config = log_group_config
        self.log = logs
        self.resolver = resolver
        self.query_log_config_name = query_log_config_name

    def _apply(self) -> None:
        log_group = self.log.find_log_group(self.log_group_config.logs_group_name)
        if log_group is None:
            raise LogsException(
                f"unable to find log group '{self.log_group_config.logs_group_name}'"
                ": this should have been created in another action before this one"
            )
        self.resolver.create_resolver_query_log_config(
            name=self.query_log_config_name, destination_arn=str(log_group.arn), tags=PLATSEC_SCANNER_TAGS
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(log_group_name=self.log_group_config.logs_group_name)
        )


@dataclass
class DeleteResolverQueryLogConfig(ComplianceAction):
    resolver: AwsResolverClient
    query_log_config_id: str

    def __init__(
        self,
        resolver: AwsResolverClient,
        query_log_config_id: str,
    ):
        super().__init__("Delete Resolver Query Log Config")
        self.resolver = resolver
        self.query_log_config_id = query_log_config_id

    def _apply(self) -> None:
        self.resolver.delete_resolver_query_log_config(id=self.query_log_config_id)

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(query_log_config_id=self.query_log_config_id)
        )


@dataclass
class DisassociateResolverQueryLogConfig(ComplianceAction):
    resolver: AwsResolverClient
    resource_id: str

    def __init__(self, resolver: AwsResolverClient, resource_id: str):
        super().__init__("Disassociate Resolver Query Log Config")
        self.resolver = resolver
        self.resource_id = resource_id

    def _apply(self) -> None:
        vpc_resolver_query_log_config_id = self.resolver.get_vpc_query_log_config_association(vpc_id=self.resource_id)
        if vpc_resolver_query_log_config_id:
            self.resolver.disassociate_resolver_query_log_config(
                resolver_quer_log_config_id=vpc_resolver_query_log_config_id, resource_id=self.resource_id
            )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(resource_id=self.resource_id),
        )


@dataclass
class AssociateResolverQueryLogConfig(ComplianceAction):
    resolver: AwsResolverClient
    log_config_name: str
    vpcs: Sequence[Vpc]

    def __init__(self, resolver: AwsResolverClient, log_config_name: str, vpcs: Sequence[Vpc]):
        super().__init__("Associate Resolver Query Log Config")
        self.resolver = resolver
        self.log_config_name = log_config_name
        self.vpcs = vpcs

    def _apply(self) -> None:
        resolver_query_log = next(
            iter(self.resolver.list_resolver_query_log_configs(query_log_config_name=self.log_config_name)), None
        )
        if resolver_query_log is not None:
            for vpc in self.vpcs:
                self.resolver.associate_resolver_query_log_config(
                    resolver_query_log_config_id=resolver_query_log.id, vpc_id=vpc.id
                )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(log_config_name=self.log_config_name, vpcs=self.vpcs)
        )


@dataclass
class DeleteQueryLogAction(ComplianceAction):
    def __init__(self, route53_client: AwsHostedZonesClient, hosted_zone_id: str):
        super().__init__("Delete Route53 query logging config")
        self.hosted_zone_id = hosted_zone_id
        self.logs = route53_client

    def _apply(self) -> None:
        self.logs.delete_query_logging_config(self.hosted_zone_id)

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(description=self.description, details=dict(hosted_zone_id=self.hosted_zone_id))


@dataclass
class CreateFlowLogAction(ComplianceAction):
    vpc_id: str
    config: Config = field(compare=False, hash=False, repr=False)
    log_group_config: LogGroupConfig

    def __init__(
        self, ec2_client: AwsEC2Client, iam: AwsIamClient, config: Config, vpc_id: str, log_group_config: LogGroupConfig
    ):
        super().__init__("Create VPC flow log")
        self.ec2 = ec2_client
        self.iam = iam
        self.vpc_id = vpc_id
        self.config = config
        self.log_group_config = log_group_config

    def _get_flow_log_delivery_role_arn(self, logs_vpc_log_group_delivery_role: str) -> str:
        return self.iam.get_role(logs_vpc_log_group_delivery_role).arn

    def _apply(self) -> None:
        self.ec2.create_flow_logs(
            self.vpc_id,
            self.log_group_config.logs_group_name,
            self._get_flow_log_delivery_role_arn(self.config.logs_vpc_log_group_delivery_role()),
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(vpc_id=self.vpc_id, log_group_name=self.log_group_config.logs_group_name),
        )


@dataclass
class CreateQueryLogAction(ComplianceAction):
    zone_id: str
    log_group_config: LogGroupConfig

    def __init__(
        self,
        account: Account,
        route53_client: AwsHostedZonesClient,
        iam: AwsIamClient,
        log_group_config: LogGroupConfig,
        zone_id: str,
    ):
        super().__init__("Create log group")
        self.route53_client = route53_client
        self.iam = iam
        self.zone_id = zone_id
        self.log_group_config = log_group_config
        self.account = account
        self.query_log_arn = (
            "arn:aws:logs:us-east-1:" + self.account.identifier + ":log-group:" + self.log_group_config.logs_group_name
        )

    def _apply(self) -> None:
        self.route53_client.create_query_logging_config(
            self.zone_id,
            self.query_log_arn,
        )

    def plan(self) -> ComplianceActionReport:

        return ComplianceActionReport(
            description=self.description,
            details=dict(zone_id=self.zone_id, log_group_name=self.log_group_config.logs_group_name),
        )


@dataclass
class CreateFlowLogDeliveryRoleAction(ComplianceAction):
    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Create delivery role for VPC flow log")
        self.iam = iam
        self.config = Config()

    def _apply(self) -> None:
        self.iam.attach_role_policy(
            self.iam.create_role(
                self.config.logs_vpc_log_group_delivery_role(),
                self.config.logs_vpc_log_group_delivery_role_assume_policy(),
            ),
            str(self.iam.find_policy_arn(self.config.logs_vpc_log_group_delivery_role_policy())),
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(role_name=Config().logs_vpc_log_group_delivery_role())
        )


@dataclass
class DeleteFlowLogDeliveryRoleAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Delete delivery role for VPC flow log")
        self.iam = iam
        self.config = Config()

    def _apply(self) -> None:
        self.iam.delete_role(self.config.logs_vpc_log_group_delivery_role())


@dataclass
class TagFlowLogDeliveryRoleAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Tag delivery role for VPC flow log")
        self.iam = iam

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(role_name=Config().logs_vpc_log_group_delivery_role(), tags=PLATSEC_SCANNER_TAGS),
        )

    def _apply(self) -> None:
        self.iam.tag_role(name=Config().logs_vpc_log_group_delivery_role(), tags=PLATSEC_SCANNER_TAGS)


@dataclass
class CreateLogGroupAction(ComplianceAction):
    logs: AwsLogsClient
    log_group_config: LogGroupConfig

    def __init__(self, logs: AwsLogsClient, log_group_config: LogGroupConfig) -> None:
        super().__init__("Create log group")
        self.logs = logs
        self.log_group_config = log_group_config

    def _apply(self) -> None:
        self.logs.create_log_group(self.log_group_config.logs_group_name)

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(log_group_name=self.log_group_config.logs_group_name)
        )


@dataclass
class PutLogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient
    log_group_config: LogGroupConfig

    def __init__(self, logs: AwsLogsClient, log_group_config: LogGroupConfig) -> None:

        super().__init__(f"Put central {log_group_config.logs_group_name} log group subscription filter")
        self.logs = logs
        self.log_group_config = log_group_config
        self.destination_arn = logs.destination_arn(config=log_group_config)

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=self.log_group_config.logs_group_name,
                destination_arn=self.destination_arn,
            ),
        )

    def _apply(self) -> None:
        self.logs.put_subscription_filter(
            log_group_name=self.log_group_config.logs_group_name,
            filter_name=self.log_group_config.logs_log_group_subscription_filter_name,
            filter_pattern=self.log_group_config.logs_log_group_pattern,
            destination_arn=self.destination_arn,
        )


@dataclass
class DeleteLogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient
    log_group_config: LogGroupConfig

    def __init__(self, logs: AwsLogsClient, log_group_config: LogGroupConfig) -> None:
        super().__init__(
            f"Delete central {log_group_config.logs_log_group_subscription_filter_name} log group subscription filter"
        )
        self.logs = logs
        self.log_group_config = log_group_config

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=self.log_group_config.logs_group_name,
                subscription_filter_name=self.log_group_config.logs_log_group_subscription_filter_name,
            ),
        )

    def _apply(self) -> None:
        self.logs.delete_subscription_filter(
            log_group_name=self.log_group_config.logs_group_name,
            filter_name=self.log_group_config.logs_log_group_subscription_filter_name,
        )


@dataclass
class PutLogGroupRetentionPolicyAction(ComplianceAction):
    logs: AwsLogsClient
    log_group_config: LogGroupConfig

    def __init__(self, logs: AwsLogsClient, log_group_config: LogGroupConfig) -> None:
        super().__init__(f"Put {log_group_config.logs_group_name} log group retention policy")
        self.logs = logs
        self.log_group_config = log_group_config

    def _apply(self) -> None:
        self.logs.put_retention_policy(
            log_group_name=self.log_group_config.logs_group_name,
            retention_days=self.log_group_config.logs_group_retention_policy_days,
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=self.log_group_config.logs_group_name,
                retention_days=self.log_group_config.logs_group_retention_policy_days,
            ),
        )


@dataclass
class PutLogGroupResourcePolicyAction(ComplianceAction):
    def __init__(self, logs: AwsLogsClient, log_group_config: LogGroupConfig, policy_document: Dict[str, Any]) -> None:
        super().__init__("Put log group resource policy")
        self.logs = logs
        self.log_group_config = log_group_config
        self.policy_document = policy_document

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                policy_name=self.log_group_config.log_group_resource_policy_name,
            ),
        )

    def _apply(self) -> None:
        self.logs.put_resource_policy(
            policy_name=self.log_group_config.log_group_resource_policy_name,
            policy_document=self.policy_document,
        )


@dataclass
class TagLogGroupAction(ComplianceAction):
    logs: AwsLogsClient
    log_group_config: LogGroupConfig

    def __init__(self, logs: AwsLogsClient, log_group_config: LogGroupConfig) -> None:
        super().__init__("Tag central log group")
        self.logs = logs
        self.log_group_config = log_group_config

    def _apply(self) -> None:
        self.logs.tag_log_group(log_group_name=self.log_group_config.logs_group_name, tags=PLATSEC_SCANNER_TAGS)

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(log_group_name=self.log_group_config.logs_group_name, tags=PLATSEC_SCANNER_TAGS),
        )


@dataclass
class UpdatePasswordPolicyAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Update IAM password policy")
        self.iam = iam

    def _apply(self) -> None:
        self.iam.update_account_password_policy(Config().iam_password_policy())

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(password_policy=Config().iam_password_policy()),
        )
