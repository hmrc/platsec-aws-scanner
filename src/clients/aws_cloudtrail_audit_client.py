from logging import getLogger
from typing import Any, Dict, List, Sequence
from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from src.data.aws_scanner_exceptions import CloudtrailException
from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try
from src.data.aws_cloudtrail_types import Trail, to_trail


class AwsCloudtrailAuditClient:
    def __init__(self, boto_cloudtrail: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cloudtrail = boto_cloudtrail

    def get_trails(self) -> Sequence[Trail]:
        try:
            return [
                self._get_trail_status(to_trail(trail)) for trail in self._cloudtrail.describe_trails()["trailList"]
            ]
        except (BotoCoreError, ClientError) as err:
            self._logger.error(f"unable to get trails: {err}")
            raise CloudtrailException(f"unable to get trails")

    def _get_trail_status(self, trail: Trail) -> Trail:
        try:
            return trail.update_logging(self._cloudtrail.get_trail_status(Name=trail.name)["IsLogging"])
        except (BotoCoreError, ClientError) as err:
            self._logger.error(f"unable to get trail status for {trail.name} : {err}")
            raise CloudtrailException(f"unable to get trail status for {trail.name}")

    @staticmethod
    def check_logfile_validation_enabled(trail) -> bool:
        return trail["LogFileValidationEnabled"]

    @staticmethod
    def check_logfile_encryption(trail) -> bool:
        key_id = "replace this with representation of the real key"
        return "KmsKeyId" in trail and trail["KmsKeyId"] is key_id
