from tests.tasks.generic_cloudtrail_test_case import GenericCloudTrailTestCase

from src.tasks.aws_service_usage_scanner_task import AwsServiceUsageScannerTask

from tests.tasks import test_aws_cloudtrail_scanner_queries as queries


class TestAwsServiceUsageScannerTask(GenericCloudTrailTestCase):
    def test_service_usage_scanner_task(self):
        self._assert_task_run(
            task_type=AwsServiceUsageScannerTask,
            task_args={"service": "ssm"},
            query=queries.SCAN_SERVICE_USAGE,
            query_results=[queries.SCAN_SERVICE_USAGE_RESULTS, []],
            results=[
                {
                    "event_source": "ssm.amazonaws.com",
                    "service_usage": [
                        {"event_name": "describe_document", "error_code": "AccessDenied", "count": 1024},
                        {"event_name": "get_inventory", "error_code": "", "count": 54},
                    ],
                },
                {"event_source": "ssm", "service_usage": []},
            ],
        )
