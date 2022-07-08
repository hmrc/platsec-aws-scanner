from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass, field
from logging import getLogger, Logger
from typing import Any, Dict, Optional

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_scanner_exceptions import AwsScannerException
from src.clients.aws_hostedZones_client import AwsHostedZonesClient
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

@dataclass
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

    def __init__(self, ec2_client: AwsEC2Client, iam: AwsIamClient, config: Config, vpc_id: str):
        super().__init__("Create VPC flow log")
        self.ec2 = ec2_client
        self.iam = iam
        self.vpc_id = vpc_id
        self.config = config

    def _get_flow_log_delivery_role_arn(self, logs_vpc_log_group_delivery_role: str) -> str:
        return self.iam.get_role(logs_vpc_log_group_delivery_role).arn

    def _apply(self) -> None:
        self.ec2.create_flow_logs(
            self.vpc_id,
            self.config.logs_vpc_log_group_name(),
            self._get_flow_log_delivery_role_arn(self.config.logs_vpc_log_group_delivery_role()),
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(vpc_id=self.vpc_id, log_group_name=self.config.logs_vpc_log_group_name()),
        )

@dataclass
class CreateQueryLogAction(ComplianceAction):
    zone_id: str
    config: Config = field(compare=False, hash=False, repr=False)

    def __init__(self, account: Account, route53_client: AwsHostedZonesClient, iam: AwsIamClient, config: Config, zone_id: str):
        super().__init__("Create hosted zone query log")
        self.route53_client = route53_client
        self.iam = iam
        self.zone_id = zone_id
        self.config = config
        self.account = account
        self.query_log_arn = "arn:aws:logs:us-east-1:" + self.account.identifier + ":log-group:" + self.config.logs_route53_log_group_name()

    def _get_query_log_delivery_role_arn(self, logs_route53_log_group_delivery_role: str) -> str:
        return self.iam.get_role(logs_route53_log_group_delivery_role).arn

    def _apply(self) -> None:
        self.route53_client.create_query_logging_config(
            self.zone_id,
            self.query_log_arn,
        )

    def plan(self) -> ComplianceActionReport:

        return ComplianceActionReport(
            description=self.description,
            details=dict(zone_id=self.zone_id, log_group_name=self.config.logs_route53_log_group_name()),
        )

@dataclass
class CreateFlowLogDeliveryRoleAction(ComplianceAction):
    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Create delivery role for VPC flow log")
        self.iam = iam

    def _apply(self) -> None:
        config = Config()
        self.iam.attach_role_policy(
            self.iam.create_role(
                config.logs_vpc_log_group_delivery_role(),
                config.logs_vpc_log_group_delivery_role_assume_policy(),
            ),
            str(self.iam.find_policy_arn(config.logs_vpc_log_group_delivery_role_policy())),
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(role_name=Config().logs_vpc_log_group_delivery_role())
        )

@dataclass
class CreateQueryLogDeliveryRoleAction(ComplianceAction):
    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Create delivery role for ROUTE53 flow log")
        self.iam = iam

    def _apply(self) -> None:
        config = Config()
        self.iam.attach_role_policy(
            self.iam.create_role(
                config.logs_route53_log_group_delivery_role(),     
                config.logs_route53_log_group_delivery_role_assume_policy(),
            ),
            str(self.iam.find_policy_arn(config.logs_route53_log_group_delivery_role_policy())),
        )

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(role_name=Config().logs_route53_log_group_delivery_role())
        )

@dataclass
class DeleteFlowLogDeliveryRoleAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Delete delivery role for VPC flow log")
        self.iam = iam

    def _apply(self) -> None:
        config = Config()
        self.iam.delete_role(config.logs_vpc_log_group_delivery_role())

@dataclass
class DeleteQueryLogDeliveryRoleAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Delete delivery role for route53 flow log")
        self.iam = iam

    def _apply(self) -> None:
        config = Config()
        self.iam.delete_role(config.logs_route53_log_group_delivery_role())
        
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
class TagQueryLogDeliveryRoleAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Tag delivery role for ROUTE53 flow log")
        self.iam = iam

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description,
            details=dict(role_name=Config().logs_route53_log_group_delivery_role(), tags=PLATSEC_SCANNER_TAGS),
        )

    def _apply(self) -> None:
        self.iam.tag_role(name=Config().logs_route53_log_group_delivery_role(), tags=PLATSEC_SCANNER_TAGS)
        
@dataclass
class CreateVpcLogGroupAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Create central VPC log group")
        self.logs = logs

    def _apply(self) -> None:
        self.logs.create_log_group(Config().logs_vpc_log_group_name())

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(log_group_name=Config().logs_vpc_log_group_name())
        )

@dataclass
class CreateRoute53LogGroupAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Create central Route53 log group")
        self.logs = logs

    def _apply(self) -> None:
        self.logs.create_log_group(Config().logs_route53_log_group_name())

    def plan(self) -> ComplianceActionReport:
        return ComplianceActionReport(
            description=self.description, details=dict(log_group_name=Config().logs_route53_log_group_name())
        )

@dataclass
class PutVpcLogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Put central VPC log group subscription filter")
        self.logs = logs

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=config.logs_vpc_log_group_name(), destination_arn=config.logs_vpc_log_group_destination()
            ),
        )

    def _apply(self) -> None:
        config = Config()
        self.logs.put_subscription_filter(
            log_group_name=config.logs_vpc_log_group_name(),
            filter_name=config.logs_vpc_log_group_subscription_filter_name(),
            filter_pattern=config.logs_vpc_log_group_pattern(),
            destination_arn=config.logs_vpc_log_group_destination(),
        )

@dataclass
class PutRoute53LogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Put central Route53 log group subscription filter")
        self.logs = logs

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=config.logs_route53_log_group_name(), destination_arn=config.logs_route53_log_group_destination()
            ),
        )

    def _apply(self) -> None:
        config = Config()
        self.logs.put_subscription_filter(
            log_group_name=config.logs_route53_log_group_name(),
            filter_name=config.logs_route53_log_group_subscription_filter_name(),
            filter_pattern=config.logs_route53_log_group_pattern(),
            destination_arn=config.logs_route53_log_group_destination(),
        )


@dataclass
class DeleteVpcLogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Delete central VPC log group subscription filter")
        self.logs = logs

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=config.logs_vpc_log_group_name(),
                subscription_filter_name=config.logs_vpc_log_group_subscription_filter_name(),
            ),
        )

    def _apply(self) -> None:
        config = Config()
        self.logs.delete_subscription_filter(
            log_group_name=config.logs_vpc_log_group_name(),
            filter_name=config.logs_vpc_log_group_subscription_filter_name(),
        )

@dataclass
class DeleteRoute53LogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Delete central VPC log group subscription filter")
        self.logs = logs

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=config.logs_route53_log_group_name(),
                subscription_filter_name=config.logs_route53_log_group_subscription_filter_name(),
            ),
        )

    def _apply(self) -> None:
        config = Config()
        self.logs.delete_subscription_filter(
            log_group_name=config.logs_vpc_log_group_name(),
            filter_name=config.logs_vpc_log_group_subscription_filter_name(),
        )

@dataclass
class PutVpcLogGroupRetentionPolicyAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Put central VPC log group retention policy")
        self.logs = logs

    def _apply(self) -> None:
        config = Config()
        self.logs.put_retention_policy(
            log_group_name=config.logs_vpc_log_group_name(),
            retention_days=config.logs_vpc_log_group_retention_policy_days(),
        )

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=config.logs_vpc_log_group_name(),
                retention_days=config.logs_vpc_log_group_retention_policy_days(),
            ),
        )

@dataclass
class PutRoute53LogGroupRetentionPolicyAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Put central Route53 log group retention policy")
        self.logs = logs

    def _apply(self) -> None:
        config = Config()
        self.logs.put_retention_policy(
            log_group_name=config.logs_route53_log_group_name(),
            retention_days=config.logs_route53_log_group_retention_policy_days(),
        )

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(
                log_group_name=config.logs_route53_log_group_name(),
                retention_days=config.logs_route53_log_group_retention_policy_days(),
            ),
        )


@dataclass
class TagVpcLogGroupAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Tag central VPC log group")
        self.logs = logs

    def _apply(self) -> None:
        config = Config()
        self.logs.tag_log_group(log_group_name=config.logs_vpc_log_group_name(), tags=PLATSEC_SCANNER_TAGS)

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(log_group_name=config.logs_vpc_log_group_name(), tags=PLATSEC_SCANNER_TAGS),
        )

@dataclass
class TagRoute53LogGroupAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Tag central ROUTE53 log group")
        self.logs = logs

    def _apply(self) -> None:
        config = Config()
        self.logs.tag_log_group(log_group_name=config.logs_route53_log_group_name(), tags=PLATSEC_SCANNER_TAGS)

    def plan(self) -> ComplianceActionReport:
        config = Config()
        return ComplianceActionReport(
            description=self.description,
            details=dict(log_group_name=config.logs_route53_log_group_name(), tags=PLATSEC_SCANNER_TAGS),
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
