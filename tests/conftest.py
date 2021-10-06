from datetime import date
from os import environ
from unittest.mock import patch, Mock

environ["AWS_SCANNER_CONFIG_FILE_NAME"] = "aws_scanner_test_config.ini"
patch("boto3.session.Session.get_available_regions", return_value=["us", "eu"]).start()
patch("datetime.date", Mock(today=Mock(return_value=date(2020, 11, 2)))).start()
