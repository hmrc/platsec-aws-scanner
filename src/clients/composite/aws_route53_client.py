from logging import getLogger
from typing import Any

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.aws_scanner_config import AwsScannerConfig as Config

from src.data.aws_scanner_exceptions import HostedZonesException, QueryLogException


class AwsRoute53Client:
    def __init__(self, boto_route53: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._route53 = boto_route53

    def list_hosted_zones(self) -> Any:
        try:
            return self._route53.list_hosted_zones()
        except (BotoCoreError, ClientError) as err:
            raise HostedZonesException(f"unable to get the list of hosted zones: {err}")

    def list_query_logging_configs(self, id: str) -> Any:
        try:
            return self._route53.list_query_logging_configs(HostedZoneId=id)
        except (BotoCoreError, ClientError) as err:
            raise QueryLogException(f"unable to get the query log config: {err}")

    def create_query_logging_config(self, hosted_zone_id: str, cloudwatch_logs_loggrouparn: str) -> Any:
        return self._route53.create_query_logging_config(
            HostedZoneId=hosted_zone_id, CloudWatchLogsLogGroupArn=cloudwatch_logs_loggrouparn
        )
