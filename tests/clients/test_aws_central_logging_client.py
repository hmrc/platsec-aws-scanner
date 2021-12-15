from unittest.mock import Mock

from src.clients.composite.aws_central_logging_client import AwsCentralLoggingClient

from tests.test_types_generator import bucket


def client(s3: Mock = Mock()) -> AwsCentralLoggingClient:
    return AwsCentralLoggingClient(s3)


def test_get_event_bucket() -> None:
    the_policy = {"banana": 1}
    s3_client = Mock(
        get_bucket_policy=Mock(side_effect=lambda b: the_policy if b == "cloudtrail-logs-bucket" else None)
    )
    actual_bucket = client(s3=s3_client).get_event_bucket()
    assert actual_bucket == bucket(name="cloudtrail-logs-bucket", policy=the_policy)


def test_get_event_bucket_does_not_exist() -> None:
    s3_client = Mock(get_bucket_policy=Mock(return_value=None))
    assert client(s3=s3_client).get_event_bucket() is None
