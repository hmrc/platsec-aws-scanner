import dataclasses
import datetime
from unittest.mock import Mock, call
from tests.test_types_generator import account

from src.tasks.aws_audit_iam_task import AwsAuditIamTask
from src.data.aws_iam_types import AccessKey, User

from tests.test_types_generator import TEST_REGION


def test_run_task() -> None:
    user1 = User(user_name="user1")
    user2 = User(user_name="user2")
    users = [user1, user2]
    user1_key1 = AccessKey(
        id="keyid1",
        user_name=user1.user_name,
        created=datetime.datetime(2021, 11, 1, 17, 10, 0),
    )
    user2_key1 = AccessKey(
        id="u2key1",
        user_name=user2.user_name,
        created=datetime.datetime(2020, 10, 15, 1, 23, 27),
    )
    user2_key2 = AccessKey(
        id="u2key2",
        user_name=user2.user_name,
        created=datetime.datetime(2021, 4, 29, 9, 55, 43),
    )
    last_used = [
        datetime.datetime(2021, 11, 2, 8, 45, 12),
        None,
        datetime.datetime(2021, 5, 5, 14, 34, 23),
    ]
    iam_client = Mock(
        list_users=Mock(return_value=users),
        list_access_keys=Mock(side_effect=[[user1_key1], [user2_key1, user2_key2]]),
        get_access_key_last_used=Mock(side_effect=last_used),
    )
    expected_report = {
        "iam_access_keys": [
            dataclasses.replace(user1_key1, last_used=last_used[0]),
            dataclasses.replace(user2_key1),
            dataclasses.replace(user2_key2, last_used=last_used[2]),
        ]
    }

    assert expected_report == AwsAuditIamTask(account=account(), region=TEST_REGION)._run_task(iam_client)

    assert iam_client.list_access_keys.call_args_list == [call(user1), call(user2)]
    assert iam_client.get_access_key_last_used.call_args_list == [
        call(user1_key1),
        call(user2_key1),
        call(user2_key2),
    ]
