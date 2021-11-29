from unittest.mock import Mock

from tests.test_types_generator import audit_password_policy_task, password_policy, update_password_policy_action


def test_run_task_when_password_policy_is_compliant() -> None:
    policy = password_policy()
    client = Mock(get_account_password_policy=Mock(return_value=policy))
    expected_task_report = {"password_policy": policy, "enforcement_actions": []}
    assert audit_password_policy_task()._run_task(client) == expected_task_report


def test_run_task_when_policy_is_not_compliant() -> None:
    policy = password_policy(minimum_password_length=1)
    client = Mock(get_account_password_policy=Mock(return_value=policy))
    expected_task_report = {
        "password_policy": policy,
        "enforcement_actions": [update_password_policy_action().plan()],
    }
    assert audit_password_policy_task()._run_task(client) == expected_task_report


def test_run_task_with_compliance_enforcement() -> None:
    policy = password_policy(minimum_password_length=1)
    client = Mock(get_account_password_policy=Mock(return_value=policy))
    expected_task_report = {
        "password_policy": policy,
        "enforcement_actions": [update_password_policy_action().apply()],
    }
    assert audit_password_policy_task(enforce=True)._run_task(client) == expected_task_report
