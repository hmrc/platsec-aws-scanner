from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock, call

from src.clients.aws_s3_client import AwsS3Client

from tests.clients import test_aws_s3_client_responses as responses


class TestAwsS3Client(AwsScannerTestCase):
    def test_list_objects(self) -> None:
        mock_s3 = Mock(
            list_objects_v2=Mock(
                side_effect=[
                    responses.LIST_OBJECTS_V2_PAGE_1,
                    responses.LIST_OBJECTS_V2_PAGE_2,
                    responses.LIST_OBJECTS_V2_PAGE_3,
                ]
            )
        )
        self.assertEqual(responses.LIST_OBJECTS_V2_ALL_OBJECTS, AwsS3Client(mock_s3).list_objects("some_bucket"))
        self.assertEqual(
            [
                call.list_objects_v2(Bucket="some_bucket"),
                call.list_objects_v2(Bucket="some_bucket", ContinuationToken="token_for_page_2"),
                call.list_objects_v2(Bucket="some_bucket", ContinuationToken="token_for_page_3"),
            ],
            mock_s3.mock_calls,
        )

    def test_list_cloudtrail_enabled_account_ids(self) -> None:
        mock_results = Mock(search=Mock(return_value=responses.PAGINATE_RESULTS))
        mock_paginator = Mock(paginate=Mock(return_value=mock_results))
        mock_s3 = Mock(get_paginator=Mock(return_value=mock_paginator))
        cloudtrail_enabled_accounts = AwsS3Client(mock_s3).list_cloudtrail_enabled_account_ids()
        self.assertEqual(["030595205467", "132732819913", "260671066465"], cloudtrail_enabled_accounts)
        mock_s3.get_paginator.assert_called_once_with("list_objects_v2")
        mock_paginator.paginate.assert_called_once_with(
            Bucket="cloudtrail-logs-bucket", Delimiter="/", Prefix="AWSLogs/"
        )
        mock_results.search.assert_called_once_with("CommonPrefixes")
