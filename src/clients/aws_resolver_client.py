from dataclasses import dataclass
from logging import getLogger
from typing import Dict, Any, List, Sequence, Optional

from tenacity import retry, wait_random_exponential, stop_after_attempt  # type: ignore

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.data.aws_common_types import Tag
from src.data.aws_scanner_exceptions import ResolverException


@dataclass
class ResolverQueryLogConfig:
    name: str
    id: str
    arn: str
    destination_arn: str


class AwsResolverClient:
    resolver: BaseClient

    def __init__(self, resolver: BaseClient):
        self.__logger = getLogger(self.__class__.__name__)
        self.resolver = resolver

    def list_resolver_query_log_configs(self, query_log_config_name: str) -> List[ResolverQueryLogConfig]:
        try:
            response = self.resolver.list_resolver_query_log_configs(
                Filters=[
                    {
                        "Name": "Name",
                        "Values": [
                            query_log_config_name,
                        ],
                    },
                ]
            )
        except (BotoCoreError, ClientError) as err:
            raise ResolverException(f"unable to run list_resolver_query_log_configs: {err}")

        resolver_query_log_configs = response["ResolverQueryLogConfigs"]
        return list(map(self.__to_resolver_query_log_config, resolver_query_log_configs))

    @staticmethod
    def __to_resolver_query_log_config(response: Dict[str, Any]) -> ResolverQueryLogConfig:
        return ResolverQueryLogConfig(
            name=response["Name"],
            id=response["Id"],
            arn=response["Arn"],
            destination_arn=response["DestinationArn"],
        )

    def create_resolver_query_log_config(
        self, name: str, destination_arn: str, tags: Sequence[Tag]
    ) -> ResolverQueryLogConfig:
        tags_dictionary = [tag.to_dict() for tag in tags]
        try:
            response = self.resolver.create_resolver_query_log_config(
                Name=name, DestinationArn=destination_arn, Tags=tags_dictionary
            )
            return self.__to_resolver_query_log_config(response["ResolverQueryLogConfig"])

        except (BotoCoreError, ClientError) as err:
            raise ResolverException(
                f"unable to create_resolver_query_log_config with name '{name}' and destination_arn '{destination_arn}'"
                f": {err}"
            )

    @retry(wait=wait_random_exponential(multiplier=10, max=30), stop=stop_after_attempt(5), reraise=True)
    def delete_resolver_query_log_config(self, id: str) -> None:
        try:
            self.resolver.delete_resolver_query_log_config(ResolverQueryLogConfigId=id)
        except (BotoCoreError, ClientError) as err:
            raise ResolverException(f"unable to delete_resolver_query_log_config with id '{id}': {err}")

    @retry(wait=wait_random_exponential(multiplier=10, max=30), stop=stop_after_attempt(5), reraise=True)
    def associate_resolver_query_log_config(self, resolver_query_log_config_id: str, vpc_id: str) -> None:
        try:
            self.resolver.associate_resolver_query_log_config(
                ResolverQueryLogConfigId=resolver_query_log_config_id, ResourceId=vpc_id
            )
        except (BotoCoreError, ClientError) as err:
            raise ResolverException(
                f"unable to associate_resolver_query_log_config with from '{resolver_query_log_config_id}': {err}"
            )

    def disassociate_resolver_query_log_config(self, resolver_quer_log_config_id: str, resource_id: str) -> None:
        try:
            self.resolver.disassociate_resolver_query_log_config(
                ResolverQueryLogConfigId=resolver_quer_log_config_id, ResourceId=resource_id
            )
        except (BotoCoreError, ClientError) as err:
            raise ResolverException(
                f"unable to disassociate_resolver_query_log_config with from resourceId '{resource_id}': {err}"
            )

    def query_log_config_association_exists(self, vpc_id: str, resolver_query_log_config_id: str) -> bool:
        association = self.__list_config_associations(vpc_id=vpc_id)

        for item in association["ResolverQueryLogConfigAssociations"]:
            if item["ResolverQueryLogConfigId"] == resolver_query_log_config_id:
                return True
        return False

    def get_vpc_query_log_config_association(self, vpc_id: str) -> Optional[str]:
        association = self.__list_config_associations(vpc_id=vpc_id)

        if association and len(association["ResolverQueryLogConfigAssociations"]) > 0:
            return str(association["ResolverQueryLogConfigAssociations"][0]["ResolverQueryLogConfigId"])
        else:
            return None

    def __list_config_associations(self, vpc_id: str) -> Dict[str, Any]:
        try:
            association: Dict[str, Any] = self.resolver.list_resolver_query_log_config_associations(
                Filters=[{"Name": "ResourceId", "Values": [vpc_id]}]
            )

        except (BotoCoreError, ClientError) as err:
            raise ResolverException(
                "unable to list_resolver_query_log_config_associations" f" with vpc id '{vpc_id}': {err}"
            )
        return association
