from unittest.mock import Mock

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from tests.test_types_generator import bucket
""" from src.data.aws_s3_types import Bucket
from typing import List """


def client(s3: Mock = Mock(), kms: Mock = Mock()) -> AwsS3KmsClient:
    return AwsS3KmsClient(s3, kms)


def test_list_buckets() -> None:
    test_buckets = [bucket("bucket1"), bucket("bucket2"), bucket("bucket3")]
    s3_client = Mock(
        list_buckets=Mock(return_value=test_buckets),
    )

    buckets_result = client(s3=s3_client).list_buckets()
    assert len(buckets_result) == 3


""" def test_list_buckets_return_empty() -> None:
    test_buckets = List
    s3_client = Mock(
        list_buckets=Mock(return_value=test_buckets),
    )

    buckets_result = client(s3=s3_client).list_buckets()
    assert len(buckets_result) == 0


def test_enrich_bucket_returns_bucket() -> None:
    bucket = Bucket(name="test_bucket")
    result = client().enrich_bucket(bucket)

    assert bucket == result
 """
