from logging import getLogger
from typing import Sequence

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from src.aws_scanner_config import AwsScannerConfig as Config
from src.data.aws_scanner_exceptions import LogsException
from src.data.aws_logs_types import LogGroup, SubscriptionFilter, to_log_group, to_subscription_filter


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
        return log_group

    def describe_subscription_filters(self, log_group_name: str) -> Sequence[SubscriptionFilter]:
        try:
            return [
                to_subscription_filter(sf)
                for sf in self._logs.describe_subscription_filters(logGroupName=log_group_name)["subscriptionFilters"]
            ]
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to describe subscription filters for '{log_group_name}': {err}") from None

    def create_log_group(self, name: str) -> None:
        try:
            self._logs.create_log_group(logGroupName=name)
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to create log group with name '{name}': {err}") from None

    def put_subscription_filter(
        self, log_group_name: str, filter_name: str, filter_pattern: str, destination_arn: str
    ) -> None:
        try:
            self._logs.put_subscription_filter(
                logGroupName=log_group_name,
                filterName=filter_name,
                filterPattern=filter_pattern,
                destinationArn=destination_arn,
            )
        except (BotoCoreError, ClientError) as err:
            raise LogsException(f"unable to put subscription filter '{filter_name}': {err}") from None
