from __future__ import annotations

from unittest import TestCase
from unittest import mock
from unittest.mock import Mock, call

from src.clients.aws_hostedZones_client import AwsHostedZonesClient
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
                {
                    "Id": "/hostedzone/IIIIIIILLLLLLL",
                    "Name": "public.aws.scanner.gov.uk.",
                    "CallerReference": "string",
                    "Config": {"Comment": "string", "PrivateZone": False},
                    "ResourceRecordSetCount": 123,
                    "LinkedService": {"ServicePrincipal": "string", "Description": "string"},
                },
            ],
        }
        
       
        
        boto_mock = Mock(list_hosted_zones=Mock(return_value=expected_zones))
        
        expected_query_log_AAAABBBBCCCCDD = {
                        "QueryLoggingConfigs": [
                            {
                                "Id": "abcdefgh-1234-5678-90ab-ijklmnopqrst",
                                "HostedZoneId": "AAAABBBBCCCCDD",
                                "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123456789012:\
log-group:/aws/route53/public.aws.scanner.gov.uk.",
                    }
                ]
            }
        
        expected_query_log_IIIIIIILLLLLLL = {
                        "QueryLoggingConfigs": [
                            {
                                "Id": "abcdefgh-1234-5678-90ab-ijklmnopqrst",
                                "HostedZoneId": "IIIIIIILLLLLLL",
                                "CloudWatchLogsLogGroupArn": "",
                    }
                ]
            }
        
        values = {'AAAABBBBCCCCDD': expected_query_log_AAAABBBBCCCCDD, 'IIIIIIILLLLLLL': expected_query_log_IIIIIIILLLLLLL}
      
        boto_mock.list_query_logging_configs = Mock(side_effect = lambda HostedZoneId: values[HostedZoneId])

        assert responses.EXPECTED_LIST_HOSTED_ZONES == AwsHostedZonesClient(boto_mock).list_hosted_zones()

        boto_mock.list_hosted_zones.assert_called_once_with()

    def side_effect(HostedZoneId : str):
           
            return values[HostedZoneId]
        
        
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

        assert responses.EXPECTED_QUERY_LOG == AwsHostedZonesClient(boto_mock).list_query_logging_configs("AAAABBBBCCCCDD")

        boto_mock.list_query_logging_configs.assert_called_once_with(HostedZoneId="AAAABBBBCCCCDD")

    def test_list_query_logging_configs_failure(self) -> None:
        boto_mock = Mock(
            list_query_logging_configs=Mock(
                side_effect=client_error(
                    "listQueryLoggingConfigs", "QueryLogException", "unable to get the query log config"
                )
            )
        )

        with self.assertRaisesRegex(QueryLogException, "unable to get the query log config"):
            AwsHostedZonesClient(boto_mock).list_query_logging_configs("AAAABBBBCCCCDD")

    def test_create_query_log_config(self) -> None:

        route53_client = Mock(create_query_logging_config=Mock(return_value="expected_query_log"))
        
        expected_list_query_logging_config= {
            'QueryLoggingConfigs': [
                {
                    'Id': '1234567-1234567-1234567-1234567-1234567',
                    'HostedZoneId': 'AAAABBBBCCCCDD',
                    'CloudWatchLogsLogGroupArn': "",
                },
            ],
            'NextToken': 'string'
        }
        
        route53_client.list_query_logging_configs = Mock(side_effect = lambda HostedZoneId: expected_list_query_logging_config)
        
        AwsHostedZonesClient(route53_client).create_query_logging_config(
            "AAAABBBBCCCCDD", "arn:aws:logs:us-east-1:123456789012:log-group:/aws/route53/public.aws.scanner.gov.uk."
        )
        
        assert route53_client.list_query_logging_configs.call_count == 1
        assert route53_client.create_query_logging_config.call_count == 1
        
        route53_client.create_query_logging_config.assert_has_calls(
            [
                call(
                    HostedZoneId="AAAABBBBCCCCDD",
                    CloudWatchLogsLogGroupArn="arn:aws:logs:us-east-1:123456789012:log-group:\
/aws/route53/public.aws.scanner.gov.uk.",
                )
            ]
        )
        
    def test_delete_query_logging_config(self) -> None:

        route53_client = Mock(create_query_logging_config=Mock(return_value="expected_query_log"))
        
        expected_list_query_logging_config= {
            'QueryLoggingConfigs': [
                {
                    'Id': '1234567-1234567-1234567-1234567-1234567',
                    'HostedZoneId': 'AAAABBBBCCCCDD',
                    'CloudWatchLogsLogGroupArn': "arn:aws:logs:us-east-1:123456789012:log-group:\
/aws/route53/public.aws.scanner.gov.uk.",
                },
            ],
            'NextToken': 'string'
        }
        
        route53_client.list_query_logging_configs = Mock(side_effect = lambda HostedZoneId: expected_list_query_logging_config)
        
        AwsHostedZonesClient(route53_client).delete_query_logging_config("AAAABBBBCCCCDD")
        
        assert route53_client.delete_query_logging_config.call_count == 1
     
        
