from tests.tasks.generic_cloudtrail_test_case import GenericCloudTrailTestCase

from src.tasks.aws_principal_by_ip_finder_task import AwsPrincipalByIPFinderTask

from tests.tasks import test_aws_cloudtrail_scanner_queries as queries


class TestAwsPrincipalByIPFinderTask(GenericCloudTrailTestCase):
    def test_principal_by_id_finder_task(self):
        self._assert_task_run(
            task_type=AwsPrincipalByIPFinderTask,
            task_args={"source_ip": "127.0.0.1"},
            query=queries.FIND_PRINCIPAL_BY_IP,
            query_results=[queries.FIND_PRINCIPAL_BY_ID_RESULTS, []],
            results=[
                {"principals": ["joe.bloggs", "john.doo"]},
                {"principals": []},
            ],
        )
