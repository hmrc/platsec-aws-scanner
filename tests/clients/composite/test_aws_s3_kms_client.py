from unittest.mock import Mock

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.data.aws_s3_types import Bucket


def client(s3: Mock = Mock(), kms: Mock = Mock()) -> AwsS3KmsClient:
    return AwsS3KmsClient(s3, kms)


def test_enrich_bucket_returns_bucket() -> None:
    bucket = Bucket(name="test_bucket")
    result = client().enrich_bucket(bucket)

    assert bucket == result
