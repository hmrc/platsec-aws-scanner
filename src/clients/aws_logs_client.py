from logging import getLogger
from typing import Sequence
from functools import partial
from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_common_types import Tag
from src.data.aws_logs_types import LogGroup, SubscriptionFilter, to_log_group, to_subscription_filter
from src.data.aws_scanner_exceptions import LogsException
from src.data.aws_common_types import ServiceName


class AwsLogsClient:
    def __init__(self, boto_logs: BaseClient):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._logs = boto_logs

    def describe_log_groups(self, name_prefix: str) -> Sequence[LogGroup]:
        try:
            return [
                self.enrich_log_group(to_log_group(log_group))
                for log_group in self._logs.describe_log_groups(logGroupNamePrefix=name_prefix)["logGroups"]
            ]
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to describe log groups with name prefix '{name_prefix}': {err}") from None

    def enrich_log_group(self, log_group: LogGroup) -> LogGroup:
        log_group.subscription_filters = self.describe_subscription_filters(log_group.name)
        log_group.tags = self.list_tags_log_group(log_group.name)
        return log_group

    def describe_subscription_filters(self, log_group_name: str) -> Sequence[SubscriptionFilter]:
        try:
            return [
                to_subscription_filter(sf)
                for sf in self._logs.describe_subscription_filters(logGroupName=log_group_name)["subscriptionFilters"]
            ]
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to describe subscription filters for '{log_group_name}': {err}") from None

    def list_tags_log_group(self, log_group_name: str) -> Sequence[Tag]:
        try:
            return [
                Tag(key=tag[0], value=tag[1])
                for tag in self._logs.list_tags_log_group(logGroupName=log_group_name)["tags"].items()
            ]
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to list tags for log group '{log_group_name}': {err}") from None

    def create_log_group(self, name: str) -> None:
        self._logger.debug(f"creating log group with name '{name}'")
        try:
            self._logs.create_log_group(logGroupName=name)
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to create log group with name '{name}': {err}") from None

    def tag_log_group(self, log_group_name: str, tags: Sequence[Tag]) -> None:
        try:
            self._logs.tag_log_group(logGroupName=log_group_name, tags={tag.key: tag.value for tag in tags})
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to tag log group '{log_group_name}' with tags '{tags}': {err}") from None

    def put_subscription_filter(
        self, log_group_name: str, filter_name: str, filter_pattern: str, destination_arn: str
    ) -> None:
        self._logger.debug(
            f"putting subscription filter {filter_name} with pattern {filter_pattern} and destination {destination_arn}"
        )
        try:
            self._logs.put_subscription_filter(
                logGroupName=log_group_name,
                filterName=filter_name,
                filterPattern=filter_pattern,
                destinationArn=destination_arn,
            )
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to put subscription filter '{filter_name}': {err}") from None

    def delete_subscription_filter(self, log_group_name: str, filter_name: str) -> None:
        try:
            self._logs.delete_subscription_filter(logGroupName=log_group_name, filterName=filter_name)
        except (BotoCoreError, ClientError) as err:
            raise LogsException(
                f"unable to delete subscription filter '{filter_name}' in log group '{log_group_name}': {err}"
            ) from None

    def put_retention_policy(self, log_group_name: str, retention_days: int) -> None:
        try:
            self._logs.put_retention_policy(logGroupName=log_group_name, retentionInDays=retention_days)
        except (BotoCoreError, ClientError) as err:
            raise LogsException(
                f"unable to put {retention_days} days retention policy for log group '{log_group_name}': {err}"
            ) from None

    def put_resource_policy(self, policy_name: str, policy_document: str) -> None:
        try:
            self._logs.put_resource_policy(policyName=policy_name, policyDocument=policy_document)
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to put logs resource policy': {err}") from None

    def is_central_log_group(self, log_group: LogGroup, service_name: ServiceName) -> bool:
        return log_group.name == self._config.logs_group_name(service_name) and any(
            map(partial(self.is_central_destination_filter, service_name=service_name), log_group.subscription_filters)
        )

    def is_central_destination_filter(self, sub_filter: SubscriptionFilter, service_name: ServiceName) -> bool:
        return sub_filter.filter_pattern == self._config.logs_log_group_pattern(
            service_name=service_name
        ) and sub_filter.destination_arn == self._config.logs_log_group_destination(service_name=service_name)
