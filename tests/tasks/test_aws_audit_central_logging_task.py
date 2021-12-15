from unittest.mock import Mock

from tests.test_types_generator import account, aws_audit_central_logging_task, bucket, key


def test_run_task() -> None:
    event_bucket = bucket("the_event_bucket")
    event_key = key(id="657984")
    org_accounts = [account("account-a"), account("account-b")]
    client = Mock(
        get_event_bucket=Mock(return_value=event_bucket),
        get_event_cmk=Mock(return_value=event_key),
        get_all_accounts=Mock(return_value=org_accounts),
    )
    task_report = aws_audit_central_logging_task()._run_task(client)
    assert task_report == {"events_bucket": event_bucket, "events_cmk": event_key, "org_accounts": org_accounts}
