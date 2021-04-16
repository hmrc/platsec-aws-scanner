from dataclasses import dataclass
from typing import List

from botocore.client import BaseClient

from src.data.aws_s3_types import Bucket, to_bucket


@dataclass
class ListObjectsResponse:
    objects: List[str]
    page_token: str


class AwsS3Client:
    def __init__(self, boto_s3: BaseClient):
        self._s3 = boto_s3

    def list_buckets(self) -> List[Bucket]:
        return [to_bucket(bucket) for bucket in self._s3.list_buckets()["Buckets"]]
