from __future__ import annotations

from unittest import TestCase
from unittest.mock import Mock

from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.data.aws_scanner_exceptions import HostedZonesException, QueryLogException

import tests.clients.composite.test_aws_rout53_client_responses as responses

from tests.test_types_generator import client_error


class TestRout53(TestCase):
    def test_list_zones(self) -> None:
        expected_zones = {
            "HostedZones": [
                {
                    "Id": "/hostedzone/AAAABBBBCCCCDD",
                    "Name": "public.aws.scanner.gov.uk.",
                    "CallerReference": "string",
                    "Config": {"Comment": "string", "PrivateZone": False},
                    "ResourceRecordSetCount": 123,
                    "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
                },
                {
                    "Id": "/hostedzone/EEEEFFFFGGGGHH",
                    "Name": "private.aws.scanner.gov.uk.",
                    "CallerReference": "string",
                    "Config": {"Comment": "string", "PrivateZone": True},
                    "ResourceRecordSetCount": 123,
                    "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
                },
            ],
        }

        boto_mock = Mock(list_hosted_zones=Mock(return_value=expected_zones))

        assert responses.EXPECTED_LIST_HOSTED_ZONES == AwsRoute53Client(boto_mock).list_hosted_zones()

        boto_mock.list_hosted_zones.assert_called_once_with()

    def test_list_hosted_zones_failure(self) -> None:
        boto_mock = Mock(
            list_hosted_zones=Mock(
                side_effect=client_error(
                    "ListHostedZones", "HostedZonesException", "unable to get the list of hosted zones"
                )
            )
        )
        with self.assertRaisesRegex(HostedZonesException, "unable to get the list of hosted zones"):
            AwsRoute53Client(boto_mock).list_hosted_zones()

    def test_list_query_logging_configs(self) -> None:
        expected_query_log = {
            "QueryLoggingConfigs": [
                {
                    "Id": "abcdefgh-1234-5678-90ab-ijklmnopqrst",
                    "HostedZoneId": "AAAABBBBCCCCDD",
                    "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:\
log-group:/aws/route53/public.aws.scanner.gov.uk.",
                }
            ]
        }

        boto_mock = Mock(list_query_logging_configs=Mock(return_value=expected_query_log))

        arg = {"HostedZoneId": "AAAABBBBCCCCDD"}

        assert responses.EXPECTED_QUERY_LOG == AwsRoute53Client(boto_mock).list_query_logging_configs("AAAABBBBCCCCDD")

        boto_mock.list_query_logging_configs.assert_called_once_with(arg)

    def test_list_query_logging_configs_failure(self) -> None:
        boto_mock = Mock(
            list_query_logging_configs=Mock(
                side_effect=client_error(
                    "listQueryLoggingConfigs", "QueryLogException", "unable to get the query log config"
                )
            )
        )

        with self.assertRaisesRegex(QueryLogException, "unable to get the query log config"):
            AwsRoute53Client(boto_mock).list_query_logging_configs("AAAABBBBCCCCDD")
