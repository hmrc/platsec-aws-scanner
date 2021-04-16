from dataclasses import dataclass
from typing import Dict, List

from botocore.client import BaseClient

from src.aws_scanner_config import AwsScannerConfig as Config


@dataclass
class ListObjectsResponse:
    objects: List[str]
    page_token: str


class AwsS3Client:
    def __init__(self, boto_s3: BaseClient):
        self._s3 = boto_s3

    def list_cloudtrail_enabled_account_ids(self) -> List[str]:
        paginator = self._s3.get_paginator("list_objects_v2")
        results = paginator.paginate(Bucket=Config().bucket_cloudtrail_logs(), Delimiter="/", Prefix="AWSLogs/")
        return [prefix["Prefix"].split("/")[1] for prefix in results.search("CommonPrefixes")]

    def list_objects(self, bucket: str) -> List[str]:
        objects: List[str] = []
        page_token = ""
        while page_token := self._fetch_objects_page(bucket, objects, page_token):
            pass
        return objects

    def _fetch_objects_page(self, bucket: str, objects: List[str], page_token: str = "") -> str:
        response = self._s3.list_objects_v2(**self._build_list_objects_arguments(bucket, page_token))
        objects += [obj["Key"] for obj in response["Contents"]]
        return str(response["NextContinuationToken"]) if response["IsTruncated"] else ""

    @staticmethod
    def _build_list_objects_arguments(bucket: str, page_token: str) -> Dict[str, str]:
        return {"Bucket": bucket, "ContinuationToken": page_token} if page_token else {"Bucket": bucket}
