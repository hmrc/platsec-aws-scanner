import os
import sys

from configparser import ConfigParser
from logging import getLogger
from typing import List

from src.data.aws_organizations_types import Account


class AwsScannerConfig:
    def __init__(self) -> None:
        self._logger = getLogger(self.__class__.__name__)
        self._config = self._load_config()

    def account_auth(self) -> Account:
        return Account(self._get_config("accounts", "auth"), "auth")

    def account_cloudtrail(self) -> Account:
        return Account(self._get_config("accounts", "cloudtrail"), "cloudtrail")

    def account_root(self) -> Account:
        return Account(self._get_config("accounts", "root"), "root")

    def athena_database_prefix(self) -> str:
        return self._get_config("athena", "database_prefix")

    def bucket_athena_query_results(self) -> str:
        return self._get_config("buckets", "athena_query_results")

    def bucket_cloudtrail_logs(self) -> str:
        return self._get_config("buckets", "cloudtrail_logs")

    def cloudtrail_log_retention_days(self) -> int:
        return int(self._get_config("cloudtrail", "log_retention_days"))

    def org_unit_include_root_accounts(self) -> bool:
        return str(self._get_config("organizational_unit", "include_root_accounts")).lower() == "true"

    def org_unit_parent(self) -> str:
        return self._get_config("organizational_unit", "parent")

    def reports_account(self) -> Account:
        return Account(self._get_config("reports", "account"), "reports")

    def reports_bucket(self) -> str:
        return self._get_config("reports", "bucket")

    def reports_output(self) -> str:
        output = self._get_config("reports", "output")
        supported = ["stdout", "s3"]
        return output if output.lower() in supported else sys.exit(self._unsupported("reports", "output", supported))

    def reports_role(self) -> str:
        return self._get_config("reports", "role")

    def role_cloudtrail(self) -> str:
        return self._get_config("roles", "cloudtrail")

    def role_organizations(self) -> str:
        return self._get_config("roles", "organizations")

    def role_s3(self) -> str:
        return self._get_config("roles", "s3")

    def role_ssm(self) -> str:
        return self._get_config("roles", "ssm")

    def session_duration_seconds(self) -> int:
        return int(self._get_config("session", "duration_seconds"))

    def tasks_executor(self) -> int:
        return int(self._get_config("tasks", "executor"))

    def username(self) -> str:
        return self._get_config("roles", "username")

    def _get_config(self, section: str, key: str) -> str:
        try:
            return os.environ.get(f"AWS_SCANNER_{section.upper()}_{key.upper()}") or self._config[section][key]
        except KeyError:
            sys.exit(f"missing config: section '{section}', key '{key}'")

    def _load_config(self) -> ConfigParser:
        config = ConfigParser()
        if not config.read("aws_scanner_config.ini"):
            self._logger.info("Config file 'aws_scanner_config.ini' not found, using environment variables instead")
        return config

    @staticmethod
    def _unsupported(section: str, key: str, supported: List[str]) -> str:
        return f"unsupported config: section '{section}', key '{key}' (should be one of {supported})"
