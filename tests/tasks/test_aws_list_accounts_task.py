from unittest import TestCase
from unittest.mock import Mock

from src.tasks.aws_list_accounts_task import AwsListAccountsTask

from tests.test_types_generator import account


class TestAwsListAccountsTask(TestCase):
    def test_run_task(self) -> None:
        accounts = [account(), account()]
        mock_orgs_client = Mock(get_all_accounts=Mock(return_value=accounts))
        self.assertEqual({"accounts": accounts}, AwsListAccountsTask()._run_task(mock_orgs_client))
