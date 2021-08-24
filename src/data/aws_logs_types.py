from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence


@dataclass
class LogGroup:
    name: str
    subscription_filters: Optional[Sequence[SubscriptionFilter]] = None


def to_log_group(log_group: Dict[str, Any]) -> LogGroup:
    return LogGroup(name=log_group["logGroupName"])


@dataclass
class SubscriptionFilter:
    log_group_name: str
    filter_name: str
    filter_pattern: str
    destination_arn: str


def to_subscription_filter(sub_filter: Dict[str, Any]) -> SubscriptionFilter:
    return SubscriptionFilter(
        log_group_name=sub_filter["logGroupName"],
        filter_name=sub_filter["filterName"],
        filter_pattern=sub_filter["filterPattern"],
        destination_arn=sub_filter["destinationArn"],
    )
