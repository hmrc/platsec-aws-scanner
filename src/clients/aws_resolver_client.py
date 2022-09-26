from dataclasses import dataclass
from logging import getLogger
from typing import Dict, Any, List

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data.aws_scanner_exceptions import LogsException


@dataclass
class ResolverQueryLogConfig:
    name: str
    id: str
    arn: str
    destination_arn: str


class AwsResolverClient:
    def __init__(self, resolver: BaseClient):
        self.__logger = getLogger(self.__class__.__name__)
        self.__resolver = resolver

    def list_resolver_query_log_configs(self) -> List[ResolverQueryLogConfig]:
        try:
            response = self.__resolver.list_resolver_query_log_configs()
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to run list_resolver_query_log_configs: {err}")

        resolver_query_log_configs = response.get("ResolverQueryLogConfig", [])
        return list(map(self.__to_resolver_query_log_config, resolver_query_log_configs))

    @staticmethod
    def __to_resolver_query_log_config(response: Dict[str, Any]) -> ResolverQueryLogConfig:
        return ResolverQueryLogConfig(
            name=response["Name"],
            id=response["Id"],
            arn=response["Arn"],
            destination_arn=response["DestinationArn"],
        )

    def create_resolver_query_log_config(self, name: str, destination_arn: str) -> ResolverQueryLogConfig:
        try:
            response = self.__resolver.create_resolver_query_log_config(Name=name, DestinationArn=destination_arn)
            return self.__to_resolver_query_log_config(response["ResolverQueryLogConfig"])

        except (BotoCoreError, ClientError) as err:
            raise LogsException(
                f"unable to create_resolver_query_log_config with name '{name}' and destination_arn '{destination_arn}'"
                f": {err}"
            )

    def delete_resolver_query_log_config(self, id: str) -> None:
        try:
            self.__resolver.delete_resolver_query_log_config(ResolverQueryLogConfigId=id)
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to delete_resolver_query_log_config with id '{id}': {err}")
