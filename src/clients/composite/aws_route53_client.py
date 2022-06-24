from logging import getLogger
from typing import Any, Dict, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients import boto_try

from src.data.aws_scanner_exceptions import HostedZonesException

from src.data.aws_scanner_exceptions import EC2Exception

from src.data.aws_route53_types import (
    Route53_Zone,
)


class AwsRoute53Client:
    def __init__(self, boto_route53: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._route53 = boto_route53

    def get_list_hosted_zones(self) -> List[Route53_Zone]:
        try:
            return self._route53.list_hosted_zones()
        except (BotoCoreError, ClientError) as err:
            raise HostedZonesException(f"unable to get the list of hosted zones: {err}")

 
