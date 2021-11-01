import logging
import re
from datetime import datetime
from typing import Any
from unittest.mock import Mock

import pytest

from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_iam_types import User, AccessKey
from src.data.aws_scanner_exceptions import IamException
from tests.test_types_generator import client_error


def test_list_users() -> None:
    mock_boto_iam = Mock(
        get_paginator=Mock(
            return_value=Mock(
                paginate=Mock(
                    return_value=[
                        {"Users": [{"UserName": "User1"}, {"UserName": "User2"}]},
                        {
                            "Users": [{"UserName": "User3"}],
                        },
                    ]
                )
            )
        )
    )
    expected_users = [User(user_name=username) for username in ["User1", "User2", "User3"]]

    assert expected_users == AwsIamClient(mock_boto_iam).list_users()

    mock_boto_iam.get_paginator.assert_called_with("list_users")


def test_list_users_exception() -> None:
    mock_boto_iam = Mock(get_paginator=Mock(side_effect=client_error("ListKeys", "pop", "weasel")))

    with pytest.raises(IamException) as e:
        AwsIamClient(mock_boto_iam).list_users()

    assert re.search("unable to list users.*pop.*", str(e)) is not None


def test_list_access_keys() -> None:
    user_name = "User1"
    mock_boto_iam = Mock(
        get_paginator=Mock(
            return_value=Mock(
                paginate=Mock(
                    return_value=[
                        {
                            "AccessKeyMetadata": [
                                {
                                    "UserName": user_name,
                                    "AccessKeyId": "ac1",
                                    "CreateDate": datetime(2021, 11, 2, 15, 18, 12),
                                },
                                {
                                    "UserName": user_name,
                                    "AccessKeyId": "ac2",
                                    "CreateDate": datetime(2021, 10, 12, 5, 34, 3),
                                },
                            ]
                        }
                    ]
                )
            )
        )
    )
    expected_keys = [
        AccessKey(user_name=user_name, id="ac1", created=datetime(2021, 11, 2, 15, 18, 12)),
        AccessKey(user_name=user_name, id="ac2", created=datetime(2021, 10, 12, 5, 34, 3)),
    ]

    assert expected_keys == AwsIamClient(mock_boto_iam).list_access_keys(User(user_name=user_name))

    mock_boto_iam.get_paginator.assert_called_with("list_access_keys")
    mock_boto_iam.get_paginator.return_value.paginate.assert_called_with(UserName=user_name)


def test_list_access_keys_exception_logs_returns_empty_list(caplog: Any) -> None:
    mock_boto_iam = Mock(get_paginator=Mock(side_effect=client_error("ListAccessKeys", "boom", "what")))

    with caplog.at_level(logging.INFO):
        assert [] == AwsIamClient(mock_boto_iam).list_access_keys(User(user_name="Brian"))

    assert len(caplog.records) == 1
    assert caplog.records[0].levelname == "WARNING"
    assert "unable to list access keys" in caplog.text
    assert "boom" in caplog.text


def test_get_access_key_last_used() -> None:
    last_used = datetime.now()
    mock_boto_iam = Mock(get_access_key_last_used=Mock(return_value={"AccessKeyLastUsed": {"LastUsedDate": last_used}}))
    key_id = "keyId"
    key = AccessKey(user_name="user", id=key_id, created=datetime.now())

    assert last_used == AwsIamClient(mock_boto_iam).get_access_key_last_used(key)

    mock_boto_iam.get_access_key_last_used.assert_called_with(AccessKeyId=key_id)


def test_get_access_key_last_used_none() -> None:
    mock_boto_iam = Mock(get_access_key_last_used=Mock(return_value={"AccessKeyLastUsed": {}}))
    key = AccessKey(user_name="user", id="keyId", created=datetime.now())

    assert AwsIamClient(mock_boto_iam).get_access_key_last_used(key) is None


def test_get_access_key_last_used_exception_returns_none(caplog: Any) -> None:
    mock_boto_iam = Mock(
        get_access_key_last_used=Mock(side_effect=client_error("GetAccessKeyLastUsed", "bad stuff", "error"))
    )
    key = AccessKey(user_name="user", id="keyId", created=datetime.now())

    with caplog.at_level(logging.INFO):
        assert AwsIamClient(mock_boto_iam).get_access_key_last_used(key) is None

    assert len(caplog.records) == 1
    assert caplog.records[0].levelname == "WARNING"
    assert "unable to get access key last used for key: keyId" in caplog.text
    assert "bad stuff" in caplog.text
