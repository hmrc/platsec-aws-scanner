from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence


@dataclass
class LogGroup:
    name: str
    kms_key_id: Optional[str]
    subscription_filters: Sequence[SubscriptionFilter]

    def __init__(
        self,
        name: str,
        kms_key_id: Optional[str] = None,
        subscription_filters: Optional[Sequence[SubscriptionFilter]] = None,
    ):
        self.name = name
        self.kms_key_id = kms_key_id
        self.subscription_filters = subscription_filters or []


def to_log_group(log_group: Dict[str, Any]) -> LogGroup:
    return LogGroup(name=log_group["logGroupName"], kms_key_id=log_group.get("kmsKeyId"))


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
