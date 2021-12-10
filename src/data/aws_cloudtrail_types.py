from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Sequence


@dataclass
class Trail:
    name: str
    s3_bucket_name: str
    is_logging: bool
    is_multiregion_trail: bool
    kms_key_id: str
    log_file_validation_enabled: bool
    include_global_service_events: bool
    event_selectors: Sequence[EventSelector]

    def update_logging(self, val: bool) -> Trail:
        self.is_logging = val
        return self


def to_trail(trail: Dict[str, Any]) -> Trail:
    return Trail(
        name=trail.get("Name"),
        s3_bucket_name=trail.get("S3BucketName"),
        is_logging=False,
        is_multiregion_trail=trail.get("IsMultiRegionTrail"),
        kms_key_id=trail.get("KmsKeyId"),
        log_file_validation_enabled=trail.get("LogFileValidationEnabled"),
        include_global_service_events=trail.get("IncludeGlobalServiceEvents"),
        event_selectors=[],
    )


def to_event_selector(es: Dict[str, Any]) -> EventSelector:
    return None


@dataclass
class EventSelector:
    read_write_type: str
    include_management_events: bool
    data_resources: Sequence[DataResource]


@dataclass
class DataResource:
    type: str
    values: Sequence[str]
