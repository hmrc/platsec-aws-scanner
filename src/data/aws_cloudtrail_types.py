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


def to_trail(trail: Dict[str, Any]) -> Trail:
    return Trail(
        name=trail["Name"],
        s3_bucket_name=trail.get("S3BucketName") or "",
        is_logging=False,
        is_multiregion_trail=trail["IsMultiRegionTrail"],
        kms_key_id=trail.get("KmsKeyId") or "",
        log_file_validation_enabled=trail["LogFileValidationEnabled"],
        include_global_service_events=trail["IncludeGlobalServiceEvents"],
        event_selectors=[],
    )


@dataclass
class EventSelector:
    read_write_type: str
    include_management_events: bool
    data_resources: Sequence[DataResource]


def to_event_selector(es: Dict[str, Any]) -> EventSelector:
    return EventSelector(
        read_write_type=es["ReadWriteType"],
        include_management_events=es["IncludeManagementEvents"],
        data_resources=[to_data_resource(dr) for dr in es["DataResources"]],
    )


@dataclass
class DataResource:
    type: str
    values: Sequence[str]


def to_data_resource(dr: Dict[str, Any]) -> DataResource:
    return DataResource(type=dr["Type"], values=dr["Values"])
