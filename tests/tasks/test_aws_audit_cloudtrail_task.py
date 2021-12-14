from unittest.mock import Mock

from tests.test_types_generator import audit_cloudtrail_task, log_group, trail


def test_run_task() -> None:
    trails = [trail(name="trail-1"), trail(name="trail-2")]
    lg = log_group(name="bla")
    client = Mock(get_trails=Mock(return_value=trails), get_cloudtrail_log_group=Mock(return_value=lg))
    assert audit_cloudtrail_task()._run_task(client) == {"trails": trails, "log_group": lg}
