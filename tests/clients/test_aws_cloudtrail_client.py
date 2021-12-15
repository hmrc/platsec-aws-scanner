from unittest.mock import Mock

from src.clients.composite.aws_cloudtrail_client import AwsCloudtrailClient

from tests.test_types_generator import log_group

import tests.clients.test_aws_cloudtrail_responses as resp


def client(cloudtrail: Mock = Mock(), logs: Mock = Mock()) -> AwsCloudtrailClient:
    return AwsCloudtrailClient(cloudtrail, logs)


def test_get_trails_success() -> None:
    cloudtrail = Mock(
        describe_trails=Mock(return_value=resp.DESCRIBE_TRAILS),
        get_trail_status=Mock(
            side_effect=lambda **kwargs: {
                "trail-1": resp.GET_TRAIL_STATUS_IS_LOGGING,
                "trail-2": resp.GET_TRAIL_STATUS_IS_NOT_LOGGING,
            }[kwargs["Name"]]
        ),
        get_event_selectors=Mock(
            side_effect=lambda **kwargs: {
                "trail-1": resp.GET_EVENT_SELECTORS,
                "trail-2": resp.GET_EVENT_SELECTORS_EMPTY,
            }[kwargs["TrailName"]]
        ),
    )
    assert resp.EXPECTED_TRAILS == client(cloudtrail=cloudtrail).get_trails()


def test_get_cloudtrail_log_group() -> None:
    expected_log_group = log_group(name="the-cloudtrail-log-group")
    logs = Mock(
        describe_log_groups=Mock(
            side_effect=lambda prefix: [log_group(), expected_log_group] if prefix == "the-cloudtrail-log-group" else []
        )
    )
    assert client(logs=logs).get_cloudtrail_log_group() == expected_log_group


def test_get_cloudtrail_log_group_not_found() -> None:
    logs = Mock(describe_log_groups=Mock(return_value=[]))
    assert client(logs=logs).get_cloudtrail_log_group() is None
