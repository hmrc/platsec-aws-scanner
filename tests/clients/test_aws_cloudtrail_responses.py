from typing import Any, Dict

from tests.test_types_generator import trail, data_resource, event_selector

GET_TRAIL_STATUS_IS_LOGGING = {"IsLogging": True}

GET_TRAIL_STATUS_IS_NOT_LOGGING = {"IsLogging": False}

GET_EVENT_SELECTORS = {
    "EventSelectors": [
        {
            "ReadWriteType": "All",
            "IncludeManagementEvents": False,
            "DataResources": [{"Type": "some_type", "Values": ["banana"]}],
            "ExcludeManagementEventSources": ["pineapple"],
        }
    ]
}

GET_EVENT_SELECTORS_EMPTY: Dict[str, Any] = {"EventSelectors": []}

GET_TRAIL_STATUS = {"IsLogging": True, "OtherInfo": "Sorted"}

DESCRIBE_TRAILS = {
    "trailList": [
        {
            "Name": "dummy-trail-1",
            "S3BucketName": "trail-bucket-1",
            "IsMultiRegionTrail": False,
            "KmsKeyId": "998877",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-1",
            "LogFileValidationEnabled": True,
            "IncludeGlobalServiceEvents": False,
        },
        {
            "Name": "dummy-trail-2",
            "S3BucketName": "trail-bucket-2",
            "IsMultiRegionTrail": True,
            "KmsKeyId": "665544",
            "HomeRegion": "eu-west-2",
            "TrailARN": "arn:aws:cloudtrail:eu-west-2:012345678901:trail/dummy-trail-2",
            "LogFileValidationEnabled": False,
            "IncludeGlobalServiceEvents": True,
        },
    ]
}

EXPECTED_TRAILS = [
    trail(
        name="dummy-trail-1",
        s3_bucket_name="trail-bucket-1",
        is_multiregion_trail=False,
        kms_key_id="998877",
        is_logging=True,
        log_file_validation_enabled=True,
        include_global_service_events=False,
        event_selectors=[
            event_selector(
                read_write_type="All",
                include_management_events=False,
                data_resources=[data_resource(type="some_type", values=["banana"])],
            )
        ],
    ),
    trail(
        name="dummy-trail-2",
        s3_bucket_name="trail-bucket-2",
        is_multiregion_trail=True,
        kms_key_id="665544",
        is_logging=False,
        log_file_validation_enabled=False,
        include_global_service_events=True,
        event_selectors=[],
    ),
]
