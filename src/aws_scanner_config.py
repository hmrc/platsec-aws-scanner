import os
import sys

from configparser import ConfigParser
from json import JSONDecodeError, loads
from logging import getLogger
from string import Template
from typing import Any, Dict, List, Sequence

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

    def cloudtrail_logs_bucket(self) -> str:
        return self._get_config("cloudtrail", "logs_bucket")

    def cloudtrail_logs_retention_days(self) -> int:
        return int(self._get_config("cloudtrail", "logs_retention_days"))

    def cloudtrail_region(self) -> str:
        return self._get_config("cloudtrail", "region")

    def cost_usage_role(self) -> str:
        return self._get_config("cost_usage", "role")

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

    def kms_key_alias(self) -> str:
        return self._get_config("kms", "key_alias")

    def kms_key_policy_default_statement(self, account_id: str) -> Dict[str, Any]:
        return self._get_templated_json_config("kms", "key_policy_default_statement", {"account_id": account_id})

    def kms_key_policy_log_group_statement(self, account_id: str, region: str) -> Dict[str, Any]:
        return self._get_templated_json_config(
            "kms",
            "key_policy_log_group_statement",
            {"account_id": account_id, "region": region, "log_group_name": self.logs_vpc_log_group_name()},
        )

    def kms_key_policy_statements(self, account_id: str, region: str) -> Sequence[Dict[str, Any]]:
        return [
            self.kms_key_policy_default_statement(account_id),
            self.kms_key_policy_log_group_statement(account_id, region),
        ]

    def kms_role(self) -> str:
        return self._get_config("kms", "role")

    def logs_vpc_log_group_name(self) -> str:
        return self._get_config("logs", "vpc_log_group_name")

    def logs_vpc_log_group_pattern(self) -> str:
        return self._get_config("logs", "vpc_log_group_pattern")

    def logs_vpc_log_group_destination(self) -> str:
        return self._get_config("logs", "vpc_log_group_destination")

    def logs_vpc_log_group_delivery_role(self) -> str:
        return self._get_config("logs", "vpc_log_group_delivery_role")

    def logs_vpc_log_group_delivery_role_policy_name(self) -> str:
        return f"{self.logs_vpc_log_group_delivery_role()}_policy"

    def logs_vpc_log_group_delivery_role_assume_policy(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "vpc_log_group_delivery_role_assume_policy")

    def logs_vpc_log_group_delivery_role_policy_document(self) -> Dict[str, Any]:
        return self._get_json_config("logs", "vpc_log_group_delivery_role_policy_document")

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
        return int(self._get_config("session", "duration_seconds"))

    def ssm_role(self) -> str:
        return self._get_config("ssm", "role")

    def tasks_executors(self) -> int:
        return int(self._get_config("tasks", "executors"))

    def user_account(self) -> Account:
        return Account(self._get_config("user", "account"), "user")

    def user_name(self) -> str:
        return self._get_config("user", "name")

    def _get_config(self, section: str, key: str) -> str:
        try:
            return os.environ.get(f"AWS_SCANNER_{section.upper()}_{key.upper()}") or self._config[section][key]
        except KeyError:
            sys.exit(f"missing config: section '{section}', key '{key}'")

    def _get_templated_config(self, section: str, key: str, keywords: Dict[str, str]) -> str:
        try:
            return Template(self._get_config(section, key)).substitute(**keywords)
        except (ValueError, KeyError) as err:
            sys.exit(f"invalid config: section '{section}', key '{key}', error: {err}")

    @staticmethod
    def _to_json(json_str: str, section: str, key: str) -> Dict[str, Any]:
        try:
            return dict(loads(json_str))
        except JSONDecodeError as err:
            sys.exit(f"invalid config: section '{section}', key '{key}', error: {err}")

    def _get_json_config(self, section: str, key: str) -> Dict[str, Any]:
        return self._to_json(self._get_config(section, key), section, key)

    def _get_templated_json_config(self, section: str, key: str, keywords: Dict[str, str]) -> Dict[str, Any]:
        return self._to_json(self._get_templated_config(section, key, keywords), section, key)

    def _load_config(self) -> ConfigParser:
        config = ConfigParser()
        if not config.read("aws_scanner_config.ini"):
            self._logger.debug("Config file 'aws_scanner_config.ini' not found, using environment variables instead")
        return config

    @staticmethod
    def _unsupported(section: str, key: str, supported: List[str]) -> str:
        return f"unsupported config: section '{section}', key '{key}' (should be one of {supported})"
