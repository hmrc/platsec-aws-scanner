from unittest.mock import Mock

from src.clients.composite.aws_cloudtrail_client import AwsCloudtrailClient

import tests.clients.test_aws_cloudtrail_responses as resp


def test_get_trails_success() -> None:
    boto_client = Mock(
        describe_trails=Mock(return_value=resp.DESCRIBE_TRAILS),
        get_trail_status=Mock(
            side_effect=lambda **kwargs: {
                "dummy-trail-1": resp.GET_TRAIL_STATUS_IS_LOGGING,
                "dummy-trail-2": resp.GET_TRAIL_STATUS_IS_NOT_LOGGING,
            }[kwargs["Name"]]
        ),
        get_event_selectors=Mock(
            side_effect=lambda **kwargs: {
                "dummy-trail-1": resp.GET_EVENT_SELECTORS,
                "dummy-trail-2": resp.GET_EVENT_SELECTORS_EMPTY,
            }[kwargs["TrailName"]]
        ),
    )
    assert resp.EXPECTED_TRAILS == AwsCloudtrailClient(boto_client).get_trails()
