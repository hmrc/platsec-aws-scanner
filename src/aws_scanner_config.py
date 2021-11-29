import os
import sys

from configparser import ConfigParser
from json import JSONDecodeError, loads
from logging import getLogger
from typing import Any, Dict, List

from src.data.aws_iam_types import PasswordPolicy
from src.data.aws_organizations_types import Account


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

    def athena_query_timeout_seconds(self) -> int:
        return self._get_int_config("athena", "query_timeout_seconds")

    def athena_query_results_polling_delay_seconds(self) -> int:
        return self._get_int_config("athena", "query_results_polling_delay_seconds")

    def athena_query_throttling_seconds(self) -> int:
        return self._get_int_config("athena", "query_throttling_seconds")

    def cloudtrail_logs_bucket(self) -> str:
        return self._get_config("cloudtrail", "logs_bucket")

    def cloudtrail_logs_retention_days(self) -> int:
        return self._get_int_config("cloudtrail", "logs_retention_days")

    def cloudtrail_region(self) -> str:
        return self._get_config("cloudtrail", "region")

    def cost_explorer_role(self) -> str:
        return self._get_config("cost_explorer", "role")

    def ec2_role(self) -> str:
        return self._get_config("ec2", "role")

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

    def iam_password_policy_role(self) -> str:
        return self._get_config("iam", "password_policy_role")

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

    def logs_vpc_log_group_name(self) -> str:
        return self._get_config("logs", "vpc_log_group_name")

    def logs_vpc_log_group_subscription_filter_name(self) -> str:
        return f"{self.logs_vpc_log_group_name()}_sub_filter"

    def logs_vpc_log_group_pattern(self) -> str:
        return self._get_config("logs", "vpc_log_group_pattern")

    def logs_vpc_log_group_destination(self) -> str:
        return self._get_config("logs", "vpc_log_group_destination")

    def logs_vpc_log_group_delivery_role(self) -> str:
        return self._get_config("logs", "vpc_log_group_delivery_role")

    def logs_vpc_log_group_delivery_role_policy(self) -> str:
        return self._get_config("logs", "vpc_log_group_delivery_role_policy")

    def logs_vpc_log_group_delivery_role_assume_policy(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "vpc_log_group_delivery_role_assume_policy")

    def logs_vpc_log_group_delivery_role_policy_document(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "vpc_log_group_delivery_role_policy_document")

    def logs_vpc_log_group_retention_policy_days(self) -> int:
        return self._get_int_config("logs", "vpc_log_group_retention_policy_days")

    def logs_role(self) -> str:
        return self._get_config("logs", "role")

    def organization_account(self) -> Account:
        return Account(self._get_config("organization", "account"), "organization")

    def organization_role(self) -> str:
        return self._get_config("organization", "role")

    def organization_include_root_accounts(self) -> bool:
        return str(self._get_config("organization", "include_root_accounts")).lower() == "true"

    def organization_parent(self) -> str:
        return self._get_config("organization", "parent")

    def reports_output(self) -> str:
        output = self._get_config("reports", "output")
        supported = ["stdout", "s3"]
        return output if output.lower() in supported else sys.exit(self._unsupported("reports", "output", supported))

    def reports_account(self) -> Account:
        return Account(self._get_config("reports", "account"), "reports")

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
        config = ConfigParser()
        file_name = os.environ.get("AWS_SCANNER_CONFIG_FILE_NAME", "aws_scanner_config.ini")
        if not config.read(file_name):
            self._logger.debug("Config file 'aws_scanner_config.ini' not found, using environment variables instead")
        return config

    @staticmethod
    def _unsupported(section: str, key: str, supported: List[str]) -> str:
        return f"unsupported config: section '{section}', key '{key}' (should be one of {supported})"
