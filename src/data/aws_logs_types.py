from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

from src.data.aws_common_types import Tag
from src.data.aws_kms_types import Key


@dataclass
class LogGroup:
    name: str
    kms_key_id: Optional[str]
    kms_key: Optional[Key]
    retention_days: Optional[int]
    subscription_filters: Sequence[SubscriptionFilter]
    tags: Sequence[Tag]

    def __init__(
        self,
        name: str,
        kms_key_id: Optional[str] = None,
        kms_key: Optional[Key] = None,
        retention_days: Optional[int] = None,
        subscription_filters: Optional[Sequence[SubscriptionFilter]] = None,
        tags: Optional[Sequence[Tag]] = None,
    ):
        self.name = name
        self.kms_key_id = kms_key_id
        self.kms_key = kms_key
        self.retention_days = retention_days
        self.subscription_filters = subscription_filters or []
        self.tags = tags or []


def to_log_group(lg: Dict[str, Any]) -> LogGroup:
    return LogGroup(name=lg["logGroupName"], kms_key_id=lg.get("kmsKeyId"), retention_days=lg.get("retentionInDays"))


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
