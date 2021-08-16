from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

from src.aws_scanner_config import AwsScannerConfig as Config


@dataclass
class LogGroup:
    name: str
    subscription_filters: Optional[Sequence[SubscriptionFilter]] = None

    @property
    def central_vpc_log_group(self) -> bool:
        return self.name.startswith(Config().logs_central_vpc_log_group_prefix()) and bool(
            self.subscription_filters and [sf for sf in self.subscription_filters if sf.central_vpc_destination_filter]
        )


def to_log_group(log_group: Dict[str, Any]) -> LogGroup:
    return LogGroup(name=log_group["logGroupName"])


@dataclass
class SubscriptionFilter:
    log_group_name: str
    filter_name: str
    filter_pattern: str
    destination_arn: str

    @property
    def central_vpc_destination_filter(self) -> bool:
        config = Config()
        return (
            self.filter_pattern == config.logs_central_vpc_log_group_pattern()
            and self.destination_arn == config.logs_central_vpc_log_group_destination()
        )


def to_subscription_filter(sub_filter: Dict[str, Any]) -> SubscriptionFilter:
    return SubscriptionFilter(
        log_group_name=sub_filter["logGroupName"],
        filter_name=sub_filter["filterName"],
        filter_pattern=sub_filter["filterPattern"],
        destination_arn=sub_filter["destinationArn"],
    )
