from unittest import TestCase
from unittest.mock import Mock, mock_open, patch

from datetime import date

test_config = """
[athena]
account = 555666777888
role = athena_role
database_prefix = some_prefix
query_results_bucket = query-results-bucket

[cloudtrail]
logs_bucket = cloudtrail-logs-bucket
logs_retention_days = 90
region = eu

[organization]
account = 999888777666
role = orgs_role
include_root_accounts = true
parent = Parent OU

[reports]
output = stdout
account = 333222333222
role = s3_reports_role
bucket = scanner-reports-bucket

[s3]
role = s3_role

[session]
duration_seconds = 3600

[ssm]
role = ssm_role

[tasks]
executors = 10

[user]
account = 111222333444
name = joe.bloggs
"""


class AwsScannerTestCase(TestCase):
    patch("builtins.open", mock_open(read_data=test_config)).start()
    patch("boto3.session.Session.get_available_regions", return_value=["us", "eu"]).start()
    patch("datetime.date", Mock(today=Mock(return_value=date(2020, 11, 2)))).start()
