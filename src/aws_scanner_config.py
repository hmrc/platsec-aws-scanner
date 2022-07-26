import boto3
import os
import sys

from configparser import ConfigParser
from json import JSONDecodeError, loads
from logging import getLogger
from typing import Any, Dict, List, Optional

from src.clients.aws_s3_client import AwsS3Client
from src.data.aws_iam_types import PasswordPolicy
from src.data.aws_organizations_types import Account
from src.data.aws_common_types import ServiceName
from src.data import aws_scanner_exceptions as exceptions

CONFIG_FILE = "aws_scanner_config.ini"


class AwsScannerConfig:
    def __init__(self) -> None:
        self._logger = getLogger(self.__class__.__name__)
        self._config = self._load_config()

    def athena_account(self) -> Account:
        return Account(self._get_config("athena", "account"), "athena")

    def athena_role(self) -> str:
        return self._get_config("athena", "role")

    def athena_database_prefix(self) -> str:
        return self._get_config("athena", "database_prefix")

    def athena_query_results_bucket(self) -> str:
        return self._get_config("athena", "query_results_bucket")

    def athena_flow_logs_bucket(self) -> str:
        return self._get_config("athena", "flow_logs_bucket")

    def athena_query_timeout_seconds(self) -> int:
        return self._get_int_config("athena", "query_timeout_seconds")

    def athena_query_results_polling_delay_seconds(self) -> int:
        return self._get_int_config("athena", "query_results_polling_delay_seconds")

    def athena_query_throttling_seconds(self) -> int:
        return self._get_int_config("athena", "query_throttling_seconds")

    def cloudtrail_account(self) -> Account:
        return Account(self._get_config("cloudtrail", "account"), "cloudtrail")

    def cloudtrail_event_key_id(self) -> str:
        return self._get_config("cloudtrail", "event_key_id")

    def cloudtrail_log_group_name(self) -> str:
        return self._get_config("cloudtrail", "log_group_name")

    def cloudtrail_logs_bucket(self) -> str:
        return self._get_config("cloudtrail", "logs_bucket")

    def cloudtrail_logs_retention_days(self) -> int:
        return self._get_int_config("cloudtrail", "logs_retention_days")

    def cloudtrail_region(self) -> str:
        return self._get_config("cloudtrail", "region")

    def cloudtrail_role(self) -> str:
        return self._get_config("cloudtrail", "role")

    @staticmethod
    def config_bucket() -> Optional[str]:
        return os.environ.get("AWS_SCANNER_CONFIG_BUCKET")

    def cost_explorer_role(self) -> str:
        return self._get_config("cost_explorer", "role")

    def ec2_role(self) -> str:
        return self._get_config("ec2", "role")

    def route53_role(self) -> str:
        return self._get_config("route53", "role")

    def ec2_flow_log_status(self) -> str:
        return self._get_config("ec2", "flow_log_status")

    def ec2_flow_log_traffic_type(self) -> str:
        return self._get_config("ec2", "flow_log_traffic_type")

    def ec2_flow_log_format(self) -> str:
        return self._get_config("ec2", "flow_log_format")

    def iam_role(self) -> str:
        return self._get_config("iam", "role")

    def iam_audit_role(self) -> str:
        return self._get_config("iam", "audit_role")

    def iam_password_policy(self) -> PasswordPolicy:
        return PasswordPolicy(
            minimum_password_length=self.iam_password_policy_minimum_password_length(),
            require_symbols=self.iam_password_policy_require_symbols(),
            require_numbers=self.iam_password_policy_require_numbers(),
            require_uppercase_chars=self.iam_password_policy_require_uppercase_chars(),
            require_lowercase_chars=self.iam_password_policy_require_lowercase_chars(),
            allow_users_to_change_password=self.iam_password_policy_allow_users_to_change_password(),
            expire_passwords=self.iam_password_policy_max_password_age() > 0,
            max_password_age=self.iam_password_policy_max_password_age(),
            password_reuse_prevention=self.iam_password_policy_password_reuse_prevention(),
            hard_expiry=self.iam_password_policy_hard_expiry(),
        )

    def iam_password_policy_minimum_password_length(self) -> int:
        return self._get_int_config("iam", "password_policy_minimum_password_length")

    def iam_password_policy_require_symbols(self) -> bool:
        return self._get_bool_config("iam", "password_policy_require_symbols")

    def iam_password_policy_require_numbers(self) -> bool:
        return self._get_bool_config("iam", "password_policy_require_numbers")

    def iam_password_policy_require_uppercase_chars(self) -> bool:
        return self._get_bool_config("iam", "password_policy_require_uppercase_chars")

    def iam_password_policy_require_lowercase_chars(self) -> bool:
        return self._get_bool_config("iam", "password_policy_require_lowercase_chars")

    def iam_password_policy_allow_users_to_change_password(self) -> bool:
        return self._get_bool_config("iam", "password_policy_allow_users_to_change_password")

    def iam_password_policy_max_password_age(self) -> int:
        return self._get_int_config("iam", "password_policy_max_password_age")

    def iam_password_policy_password_reuse_prevention(self) -> int:
        return self._get_int_config("iam", "password_policy_password_reuse_prevention")

    def iam_password_policy_hard_expiry(self) -> bool:
        return self._get_bool_config("iam", "password_policy_hard_expiry")

    def kms_role(self) -> str:
        return self._get_config("kms", "role")

    def logs_group_name(self, service_name: ServiceName) -> str:
        log_name = ""
        if service_name == ServiceName.vpc:
            log_name = self._get_config("logs", "vpc_log_group_name")
        elif service_name == ServiceName.route53:
            log_name = self._get_config("logs", "route53_log_group_name")

        if log_name == "":
            raise exceptions.InvalidServiceNameException(f"Invalid service name {service_name}")

        return log_name

    def logs_vpc_log_group_subscription_filter_name(self) -> str:
        return f"{self.logs_group_name(ServiceName.vpc)}_sub_filter"

    def logs_vpc_log_group_pattern(self) -> str:
        return self._get_config("logs", "vpc_log_group_pattern")

    def logs_route53_log_group_pattern(self) -> str:
        return self._get_config("logs", "route53_log_group_pattern")

    def logs_vpc_log_group_destination(self) -> str:
        return self._get_config("logs", "vpc_log_group_destination")

    def logs_route53_log_group_destination(self) -> str:
        return self._get_config("logs", "route53_log_group_destination")

    def logs_vpc_log_group_delivery_role(self) -> str:
        return self._get_config("logs", "vpc_log_group_delivery_role")

    def logs_route53_log_group_delivery_role(self) -> str:
        return self._get_config("logs", "route53_log_group_delivery_role")

    def logs_vpc_log_group_delivery_role_policy(self) -> str:
        return self._get_config("logs", "vpc_log_group_delivery_role_policy")

    def logs_vpc_log_group_delivery_role_assume_policy(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "vpc_log_group_delivery_role_assume_policy")

    def logs_route53_log_group_delivery_role_assume_policy(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "route53_log_group_delivery_role_assume_policy")

    def logs_vpc_log_group_delivery_role_policy_document(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "vpc_log_group_delivery_role_policy_document")

    def logs_group_retention_policy_days(self, service_name: ServiceName) -> int:
        init_config = 0
        if service_name == ServiceName.vpc:
            init_config = self._get_int_config("logs", "vpc_log_group_retention_policy_days")
        elif service_name == ServiceName.route53:
            init_config = self._get_int_config("logs", "route53_log_group_retention_policy_days")
        return init_config

    def logs_role(self) -> str:
        return self._get_config("logs", "role")

    def organization_account(self) -> Account:
        return Account(self._get_config("organization", "account"), "organization")

    def organization_role(self) -> str:
        return self._get_config("organization", "role")

    def organization_include_root_accounts(self) -> bool:
        return self._get_bool_config("organization", "include_root_accounts")

    def organization_parent(self) -> str:
        return self._get_config("organization", "parent")

    def reports_output(self) -> str:
        output = self._get_config("reports", "output")
        supported = ["stdout", "s3"]
        return output if output.lower() in supported else sys.exit(self._unsupported("reports", "output", supported))

    def reports_account(self) -> Account:
        return Account(self._get_config("reports", "account"), "reports")

    def reports_format(self) -> str:
        format = self._get_config("reports", "format").lower()
        supported = ["json", "csv"]
        return format if format in supported else sys.exit(self._unsupported("reports", "format", supported))

    def reports_role(self) -> str:
        return self._get_config("reports", "role")

    def reports_bucket(self) -> str:
        return self._get_config("reports", "bucket")

    def s3_role(self) -> str:
        return self._get_config("s3", "role")

    def session_duration_seconds(self) -> int:
        return self._get_int_config("session", "duration_seconds")

    def ssm_role(self) -> str:
        return self._get_config("ssm", "role")

    def tasks_executors(self) -> int:
        return self._get_int_config("tasks", "executors")

    def user_account(self) -> Account:
        return Account(self._get_config("user", "account"), "user")

    def user_name(self) -> str:
        return self._get_config("user", "name")

    def vpc_peering_role(self) -> str:
        return self._get_config("vpc_peering", "role")

    def _get_config(self, section: str, key: str) -> str:
        try:
            return os.environ.get(f"AWS_SCANNER_{section.upper()}_{key.upper()}") or self._config[section][key]
        except KeyError:
            sys.exit(f"missing config: section '{section}', key '{key}'")

    def _get_int_config(self, section: str, key: str) -> int:
        try:
            return int(self._get_config(section, key))
        except ValueError as err:
            sys.exit(f"invalid config type: section '{section}', key '{key}', error: {err}")

    def _get_bool_config(self, section: str, key: str) -> bool:
        return str(self._get_config(section, key)) == "true"

    @staticmethod
    def _to_json(json_str: str, section: str, key: str) -> Dict[str, Any]:
        try:
            return dict(loads(json_str))
        except JSONDecodeError as err:
            sys.exit(f"invalid config: section '{section}', key '{key}', error: {err}")

    def _get_json_config(self, section: str, key: str) -> Dict[str, Any]:
        return self._to_json(self._get_config(section, key), section, key)

    def _load_config(self) -> ConfigParser:
        return self._load_config_from_s3() if self.config_bucket() else self._load_config_from_file()

    def _load_config_from_file(self) -> ConfigParser:
        config = ConfigParser()
        file_name = os.environ.get("AWS_SCANNER_CONFIG_FILE_NAME", CONFIG_FILE)
        if not config.read(file_name):
            self._logger.debug(f"Config file '{file_name}' not found, using environment variables instead")
        return config

    def _load_config_from_s3(self) -> ConfigParser:
        config = ConfigParser()
        config.read_string(AwsS3Client(boto3.client("s3")).get_object(str(self.config_bucket()), CONFIG_FILE))
        return config

    @staticmethod
    def _unsupported(section: str, key: str, supported: List[str]) -> str:
        return f"unsupported config: section '{section}', key '{key}' (should be one of {supported})"
