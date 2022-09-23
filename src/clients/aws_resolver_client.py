from dataclasses import dataclass
from logging import getLogger
from typing import Dict, Any, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data.aws_scanner_exceptions import LogsException


@dataclass
class ResolverQueryLogConfigs:
    name: str
    arn: str
    destination_arn: str


class AwsResolverClient:
    def __init__(self, resolver: BaseClient):
        self.__logger = getLogger(self.__class__.__name__)
        self.__resolver = resolver

    def list_resolver_query_log_configs(self) -> List[ResolverQueryLogConfigs]:
        try:
            response = self.__resolver.list_resolver_query_log_configs()
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to run list_resolver_query_log_configs: {err}") from None

        resolver_query_log_configs = response.get("ResolverQueryLogConfigs", [])
        return list(map(self.__to_resolver_query_log_config, resolver_query_log_configs))

    @staticmethod
    def __to_resolver_query_log_config(response: Dict[str, Any]) -> ResolverQueryLogConfigs:
        return ResolverQueryLogConfigs(
            name=response["Name"],
            arn=response["Arn"],
            destination_arn=response["DestinationArn"],
        )
