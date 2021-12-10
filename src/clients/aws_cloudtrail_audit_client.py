from logging import getLogger
from typing import Any, Dict, List
import re
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

    def get_trails(self) -> Dict[str, List]:
        try:
            return self._cloudtrail.describe_trails()
        except (BotoCoreError, ClientError) as err:
            self._logger.error(f"unable to get trails: {err}")
            raise CloudtrailException(f"unable to get trails")

    def get_trail_status(self, trail_name: str) -> str:
        try:
            return self._cloudtrail.get_trail_status(trail_name)
        except (BotoCoreError, ClientError) as err:
            self._logger.error(f"unable to get trail status for {trail_name} : {err}")
            raise CloudtrailException(f"unable to get trail status for {trail_name}")

    @staticmethod
    def check_logfile_validation_enabled(trail) -> bool:
        return trail["LogFileValidationEnabled"]

    @staticmethod
    def check_logfile_encryption(trail) -> bool:
        key_id = "replace this with representation of the real key"
        return "KmsKeyId" in trail and trail["KmsKeyId"] is key_id
