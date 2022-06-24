from __future__ import annotations
import logging
# import pytest

from unittest import TestCase
from unittest.mock import Mock, patch

from typing import Any, Dict
from typing import Sequence, Optional, Type, Dict, Any


from unittest import TestCase
from unittest.mock import Mock


from src.clients.composite.aws_route53_client import AwsRoute53Client
from src.data.aws_scanner_exceptions import HostedZonesException
from src.data.aws_route53_types import (
    Route53_Zone,
    QueryLog,
)
import tests.clients.composite.test_aws_rout53_client_responses as responses

from tests.test_types_generator import (
    key,
    log_group,
    query_log,
    role,
)

class TestRout53(TestCase):
    def test_list_zones(self) -> None:
            a_key = key()
            log_role = role(arn=str(query_log().deliver_log_role_arn))
            group = log_group(kms_key_id=a_key.id, kms_key=a_key)
            expected_zones = [
                Route53_Zone(
                    id="/hostedzone/AAAABBBBCCCCDD",
                    name="public.aws.scanner.gov.uk.",
                    PrivateZone="false",
                    query_logs=[query_log(deliver_log_role_arn=None, deliver_log_role=None, log_group=group)],
                ),
                Route53_Zone(
                    id="/hostedzone/EEEEFFFFGGGGHH",
                    name="private.aws.scanner.gov.uk.",
                    PrivateZone="true",
                    query_logs=[query_log(deliver_log_role=log_role, log_group_name=None)]
                )
            ]
            boto_mock = Mock(list_hosted_zones=Mock(return_value=expected_zones))
            assert responses.EXPECTED_LIST_HOSTED_ZONES == AwsRoute53Client(boto_mock).get_list_hosted_zones()
            boto_mock.list_hosted_zones.assert_called_once_with()

    
    def test_list_hosted_zones_failure(self) -> None:
            boto_mock = Mock(describe_key=Mock(side_effect=HostedZonesException()))
            with self.assertRaisesRegex(HostedZonesException, "ghost-key"): AwsRoute53Client(boto_mock).get_list_hosted_zones()
    