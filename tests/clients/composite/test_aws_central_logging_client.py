from unittest.mock import Mock

from src.clients.composite.aws_central_logging_client import AwsCentralLoggingClient

from tests.test_types_generator import account, bucket, key


def client(s3: Mock = Mock(), kms: Mock = Mock(), org: Mock = Mock()) -> AwsCentralLoggingClient:
    return AwsCentralLoggingClient(s3, kms, org)


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


def test_get_event_cmk() -> None:
    expected_key = key(id="74356589")
    kms_client = Mock(find_key=Mock(side_effect=lambda k: expected_key if k == "74356589" else None))
    actual_key = client(kms=kms_client).get_event_cmk()
    assert actual_key == expected_key


def test_get_event_cmk_not_found() -> None:
    kms_client = Mock(find_key=Mock(return_value=None))
    assert client(kms=kms_client).get_event_cmk() is None


def test_get_all_accounts() -> None:
    expected_accounts = [account("123456", "test-acc-01"), account("123456", "test-acc-01")]
    org_client = Mock(get_all_accounts=Mock(return_value=expected_accounts))
    assert client(org=org_client).get_all_accounts() == expected_accounts
