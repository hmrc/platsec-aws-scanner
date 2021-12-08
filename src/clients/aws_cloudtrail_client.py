from logging import getLogger
from typing import Any, Dict, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try
from src.data.aws_scanner_exceptions import EC2Exception


class AwsCloudtrailClient:
    def __init__(self, boto_cloudtrail: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._cloudtrail = boto_cloudtrail

    def get_trails(self):
        return self._cloudtrail.list_trails()
