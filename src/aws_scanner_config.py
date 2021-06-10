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

    def _load_config(self) -> ConfigParser:
        config = ConfigParser()
        if not config.read("aws_scanner_config.ini"):
            self._logger.info("Config file 'aws_scanner_config.ini' not found, using environment variables instead")
        return config

    @staticmethod
    def _unsupported(section: str, key: str, supported: List[str]) -> str:
        return f"unsupported config: section '{section}', key '{key}' (should be one of {supported})"
