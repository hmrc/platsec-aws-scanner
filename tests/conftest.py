from os import environ
from unittest.mock import patch
from freezegun import freeze_time


environ["AWS_SCANNER_CONFIG_FILE_NAME"] = "aws_scanner_test_config.ini"
patch("boto3.session.Session.get_available_regions", return_value=["us", "eu"]).start()

freezer = freeze_time("2020-11-02")
freezer.start()
