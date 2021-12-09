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

    @staticmethod
    def check_logfile_validation_enabled(trail) -> bool:
        if "LogFileValidationEnabled" not in trail or type(trail["LogFileValidationEnabled"]) is not bool:
            raise CloudtrailException(f"unable to determine logfile validation status")
        return trail["LogFileValidationEnabled"]

    @staticmethod
    def check_logfile_encryption(trail) -> bool:
        if "KmsKeyId" not in trail:
            return False
        compiled = re.compile(
            r"^arn:aws:kms:eu-west-2:([0-9]{12}):key/([0-9]{8})-([0-9]{4})-([0-9]{4})-([0-9]{4})-([0-9]{12})$"
        )
        return bool(compiled.match(trail["KmsKeyId"]))
