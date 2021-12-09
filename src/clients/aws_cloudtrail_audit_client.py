from logging import getLogger
from typing import Any, Dict, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from src.data.aws_scanner_exceptions import CloudtrailException
from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try


class AwsCloudtrailAuditClient:
    def __init__(self, boto_cloudtrail: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cloudtrail = boto_cloudtrail

    def _get_trails(self) -> Dict[str, List]:
        return self._cloudtrail.describe_trails()

    @staticmethod
    def _check_logfile_validation_enabled(trail) -> bool:
        if "LogFileValidationEnabled" not in trail or type(trail["LogFileValidationEnabled"]) is not bool:
            raise CloudtrailException(f"unable to get logfile validation data")
        return trail["LogFileValidationEnabled"]
