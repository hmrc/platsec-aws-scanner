from unittest.mock import Mock

from tests.test_types_generator import audit_cloudtrail_task, trail


def test_run_task() -> None:
    trails = [trail(name="trail-1"), trail(name="trail-2")]
    client = Mock(get_trails=Mock(return_value=trails))
    assert {"trails": trails} == audit_cloudtrail_task()._run_task(client)
