from tests.tasks.generic_cloudtrail_test_case import GenericCloudTrailTestCase

from src.tasks.aws_role_usage_scanner_task import AwsRoleUsageScannerTask

from tests.tasks import test_aws_cloudtrail_scanner_queries as queries


class TestAwsRoleUsageScannerTask(GenericCloudTrailTestCase):
    def test_principal_by_id_finder_task(self):
        self._assert_task_run(
            task_type=AwsRoleUsageScannerTask,
            task_args={"role": "RoleSomething"},
            query=queries.SCAN_ROLE_USAGE,
            query_results=[queries.SCAN_ROLE_USAGE_RESULTS, []],
            results=[
                {
                    "role_usage": [
                        {
                            "event_source": "cloudformation.amazonaws.com",
                            "event_name": "DescribeChangeSet",
                            "count": 15,
                        },
                        {"event_source": "s3.amazonaws.com", "event_name": "GetBucketEncryption", "count": 12},
                        {"event_source": "access-analyzer.amazonaws.com", "event_name": "ListAnalyzers", "count": 4},
                        {"event_source": "s3.amazonaws.com", "event_name": "ListBuckets", "count": 2},
                    ]
                },
                {"role_usage": []},
            ],
        )
