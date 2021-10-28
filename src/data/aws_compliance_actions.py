from __future__ import annotations
from abc import abstractmethod
from dataclasses import dataclass, field
from logging import getLogger, Logger
from typing import Any, Dict, Optional

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_scanner_exceptions import AwsScannerException


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
class DeleteFlowLogDeliveryRoleAction(ComplianceAction):
    iam: AwsIamClient

    def __init__(self, iam: AwsIamClient) -> None:
        super().__init__("Delete delivery role for VPC flow log")
        self.iam = iam

    def _apply(self) -> None:
        config = Config()
        self.iam.delete_role(config.logs_vpc_log_group_delivery_role())


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
class PutVpcLogGroupSubscriptionFilterAction(ComplianceAction):
    logs: AwsLogsClient

    def __init__(self, logs: AwsLogsClient) -> None:
        super().__init__("Put central VPC log group subscription filter")
        self.logs = logs

    def _apply(self) -> None:
        config = Config()
        log_group_name = config.logs_vpc_log_group_name()
        self.logs.put_subscription_filter(
            log_group_name=log_group_name,
            filter_name=f"{log_group_name}_sub_filter",
            filter_pattern=config.logs_vpc_log_group_pattern(),
            destination_arn=config.logs_vpc_log_group_destination(),
        )


@dataclass
class UpdateLogGroupKmsKeyAction(ComplianceAction):
    logs: AwsLogsClient
    kms: AwsKmsClient
    config: Config = field(compare=False, hash=False, repr=False)

    def __init__(self, logs: AwsLogsClient, kms: AwsKmsClient, config: Config) -> None:
        super().__init__("Update log group kms key")
        self.logs = logs
        self.kms = kms
        self.config = config

    def _apply(self) -> None:
        self.logs.associate_kms_key(
            log_group_name=self.config.logs_vpc_log_group_name(), kms_key_arn=self._get_kms_key_arn()
        )

    def _get_kms_key_arn(self) -> str:
        key_id = self.kms.get_alias(self.config.kms_key_alias()).target_key_id
        return self.kms.get_key(key_id).arn  # type: ignore # this key will exist if the kms action has run


@dataclass
class DeleteLogGroupKmsKeyAliasAction(ComplianceAction):
    kms: AwsKmsClient

    def __init__(self, kms: AwsKmsClient) -> None:
        super().__init__("Delete log group kms key alias")
        self.kms = kms

    def _apply(self) -> None:
        config = Config()
        self.kms.delete_alias(name=config.kms_key_alias())


@dataclass
class CreateLogGroupKmsKeyAction(ComplianceAction):
    kms: AwsKmsClient

    def __init__(self, kms_client: AwsKmsClient) -> None:
        super().__init__("Create log group kms key")
        self.kms = kms_client

    def _apply(self) -> Optional[Dict[str, Any]]:
        config = Config()

        key = self.kms.create_key(
            alias=config.kms_key_alias(),
            description=f"Autogenerated key for {config.kms_key_alias()} do not modify",
        )
        statements = config.kms_key_policy_statements(account_id=key.account_id, region=key.region)
        self.kms.put_key_policy_statements(key_id=key.id, statements=statements)
        return dict(key_id=key.id)


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
