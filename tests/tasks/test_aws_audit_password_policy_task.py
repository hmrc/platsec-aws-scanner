from unittest.mock import Mock

from tests.test_types_generator import audit_password_policy_task, password_policy


def test_run_task() -> None:
    policy = password_policy(minimum_password_length=24, require_uppercase_chars=True)
    client = Mock(get_account_password_policy=Mock(return_value=policy))
    assert {"password_policy": policy} == audit_password_policy_task()._run_task(client)
