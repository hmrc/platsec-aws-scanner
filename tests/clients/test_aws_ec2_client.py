import logging
import pytest

from unittest import TestCase
from unittest.mock import Mock, patch

from typing import Any, Dict

from src.clients.aws_ec2_client import AwsEC2Client
from src.data.aws_ec2_types import Vpc
from src.data.aws_scanner_exceptions import EC2Exception

from tests import _raise
from tests.clients import test_aws_ec2_client_responses as responses
from tests.test_types_generator import client_error, flow_log, vpc, account


def test_list_vpcs() -> None:
    ec2 = AwsEC2Client(Mock(), account=account())
    with patch.object(ec2, "_describe_flow_logs", side_effect=lambda v: [flow_log()] if v.id == vpc().id else None):
        with patch.object(ec2, "_describe_vpcs", return_value=[vpc()]):
            assert [vpc(flow_logs=[flow_log()])] == ec2.list_vpcs()


def test_describe_vpcs_filters_by_current_account_id() -> None:
    test_account_id = "test_id_123"
    ec2 = AwsEC2Client(Mock(), account=account(test_account_id))
    with patch.object(ec2, "_describe_flow_logs", side_effect=lambda v: [flow_log()] if v.id == vpc().id else None):
        with patch.object(ec2, "_describe_vpcs", return_value=[vpc()]) as mock_vpc:
            assert [vpc(flow_logs=[flow_log()])] == ec2.list_vpcs()
            mock_vpc.assert_called_once_with(account_id=test_account_id)


def test_describe_vpcs_empty() -> None:
    ec2_client = AwsEC2Client(Mock(describe_vpcs=Mock(return_value={"Vpcs": []})), account=account())
    assert [] == ec2_client._describe_vpcs(account_id="foo")


def test_describe_vpcs_filters_by_current_account() -> None:
    # we filter by account id as vpcs can be "shared" across accounts
    vpcs = [{"VpcId": "vpc-12312e654bf654d12"}, {"VpcId": "vpc-984a4654b65465e12"}]
    mock_describe_vpcs = Mock(return_value={"Vpcs": vpcs})
    ec2_client = AwsEC2Client(Mock(describe_vpcs=mock_describe_vpcs), account=account())
    assert [Vpc("vpc-12312e654bf654d12"), Vpc("vpc-984a4654b65465e12")] == ec2_client._describe_vpcs(
        account_id=account().identifier
    )
    mock_describe_vpcs.assert_called_once_with(Filters=[{"Name": "owner-id", "Values": ["account_id"]}])


def test_describe_vpcs_failure(caplog: Any) -> None:
    error = client_error("DescribeVpcs", "AccessDenied", "Access Denied")
    ec2_client = AwsEC2Client(Mock(describe_vpcs=Mock(side_effect=error)), account=account())
    with caplog.at_level(logging.INFO):
        assert [] == ec2_client._describe_vpcs(account_id=account().identifier)
    assert "AccessDenied" in caplog.text


def describe_flow_logs(**kwargs: Any) -> Dict[Any, Any]:
    assert "resource-id" == kwargs["Filters"][0]["Name"]
    flow_log_config = kwargs["Filters"][0]["Values"][0]
    if flow_log_config == "vpc-error":
        raise client_error("DescribeFlowLogs", "AccessDenied", "Access Denied")

    return {
        "vpc-no-flow-logs": responses.EMPTY_FLOW_LOGS,
        "vpc-with-flow-logs": responses.FLOW_LOGS,
    }[flow_log_config]


def ec2_client() -> AwsEC2Client:
    return AwsEC2Client(
        boto_ec2=Mock(
            describe_flow_logs=Mock(side_effect=describe_flow_logs), delete_flow_logs=Mock(side_effect=delete_flow_logs)
        ),
        account=account(),
    )


def test_describe_flow_logs_empty() -> None:
    assert [] == ec2_client()._describe_flow_logs(Vpc("vpc-no-flow-logs"))


def test_describe_flow_logs() -> None:
    assert responses.EXPECTED_FLOW_LOGS == ec2_client()._describe_flow_logs(Vpc("vpc-with-flow-logs"))


def test_describe_flow_logs_failure(caplog: Any) -> None:
    with caplog.at_level(logging.INFO):
        assert [] == ec2_client()._describe_flow_logs(Vpc("vpc-error"))
    assert "AccessDenied" in caplog.text
    assert "vpc-error" in caplog.text


class TestAwsEC2ClientCreateFlowLogs(TestCase):
    EXPECTED_TAGS = [
        {
            "ResourceType": "vpc-flow-log",
            "Tags": [
                {"Key": "allow-management-by-platsec-scanner", "Value": "true"},
                {"Key": "source-code", "Value": "https://github.com/hmrc/platsec-aws-scanner"},
                {"Key": "business-unit", "Value": "MDTP"},
                {"Key": "owner", "Value": "PlatSec"},
            ],
        }
    ]

    def create_flow_logs(self, **kwargs: Any) -> Any:
        self.assertEqual("VPC", kwargs["ResourceType"])
        self.assertEqual("ALL", kwargs["TrafficType"])
        self.assertEqual("cloud-watch-logs", kwargs["LogDestinationType"])
        self.assertEqual("${srcaddr} ${dstaddr}", kwargs["LogFormat"])
        self.assertEqual(self.EXPECTED_TAGS, kwargs["TagSpecifications"])
        self.assertEqual(8, len(kwargs), f"expected 8 arguments passed to create_flow_logs function, got {len(kwargs)}")
        resp_mapping: Dict[Any, Any] = {
            ("good-vpc", "lg-1", "perm-1"): lambda: responses.CREATE_FLOW_LOGS_SUCCESS,
            ("bad-vpc", "lg-2", "perm-2"): lambda: responses.CREATE_FLOW_LOGS_FAILURE,
            ("except-vpc", "lg-3", "perm-3"): lambda: _raise(client_error("CreateFlowLogs", "AccessDenied", "nope")),
        }
        return resp_mapping[(kwargs["ResourceIds"][0], kwargs["LogGroupName"], kwargs["DeliverLogsPermissionArn"])]()

    def ec2_client(self) -> AwsEC2Client:
        return AwsEC2Client(Mock(create_flow_logs=Mock(side_effect=self.create_flow_logs)), account=account())

    def test_create_flow_logs(self) -> None:
        self.ec2_client().create_flow_logs("good-vpc", "lg-1", "perm-1")

    def test_create_flow_logs_failure(self) -> None:
        with self.assertRaisesRegex(EC2Exception, "bad-vpc"):
            self.ec2_client().create_flow_logs("bad-vpc", "lg-2", "perm-2")

    def test_create_flow_logs_client_error(self) -> None:
        with self.assertRaisesRegex(EC2Exception, "except-vpc"):
            self.ec2_client().create_flow_logs("except-vpc", "lg-3", "perm-3")


def delete_flow_logs(**kwargs: Any) -> Any:
    flow_log: Dict[str, Any] = {
        "good-fl": lambda: responses.DELETE_FLOW_LOGS_SUCCESS,
        "fl-not-found": lambda: responses.DELETE_FLOW_LOGS_FAILURE,
        "bad-fl": lambda: _raise(client_error("DeleteFlowLogs", "AccessDenied", "Access Denied")),
    }
    return flow_log[kwargs["FlowLogIds"][0]]()


def test_delete_flow_logs() -> None:
    ec2_client().delete_flow_logs(flow_log_id="good-fl")


def test_delete_flow_logs_not_found() -> None:
    with pytest.raises(EC2Exception, match="bad-fl"):
        ec2_client().delete_flow_logs(flow_log_id="fl-not-found")


def test_delete_flow_logs_failure() -> None:
    with pytest.raises(EC2Exception, match="bad-fl"):
        ec2_client().delete_flow_logs(flow_log_id="bad-fl")


def test_describe_vpc_peering_connections() -> None:
    paginator_mock = Mock(paginate=Mock(side_effect=lambda **k: iter(responses.DESCRIBE_VPC_PEERING_CONNECTIONS_PAGES)))
    boto_mock = Mock(get_paginator=Mock(return_value=paginator_mock))
    assert (
        responses.EXPECTED_VPC_PEERING_CONNECTIONS
        == AwsEC2Client(boto_mock, account()).describe_vpc_peering_connections()
    )
    boto_mock.get_paginator.assert_called_once_with("describe_vpc_peering_connections")


def test_describe_vpc_peering_connections_failure() -> None:
    boto_mock = Mock(get_paginator=Mock(side_effect=client_error("GetPaginator", "AccessDenied", "boom!")))
    with pytest.raises(EC2Exception, match="boom"):
        AwsEC2Client(boto_mock, account()).describe_vpc_peering_connections()


def test_list_instances() -> None:
    paginator_mock = Mock(paginate=Mock(side_effect=lambda **k: iter(responses.DESCRIBE_INSTANCES)))
    boto_mock = Mock(
        get_paginator=Mock(side_effect=lambda func: paginator_mock if func == "describe_instances" else None),
        describe_images=Mock(
            side_effect=lambda **kwargs: {
                "ami-1234": responses.DESCRIBE_IMAGE_1234,
                "ami-5678": responses.DESCRIBE_IMAGE_5678,
            }[kwargs["ImageIds"][0]]
        ),
    )
    assert AwsEC2Client(boto_mock, account()).list_instances() == responses.EXPECTED_INSTANCES


def test_list_instances_missing_ami_data() -> None:
    paginator_mock = Mock(paginate=Mock(side_effect=lambda **k: iter(responses.DESCRIBE_INSTANCES)))
    boto_mock = Mock(
        get_paginator=Mock(side_effect=lambda func: paginator_mock if func == "describe_instances" else None),
        describe_images=Mock(
            side_effect=lambda **kwargs: {
                "ami-1234": responses.DESCRIBE_IMAGE_1234,
                "ami-5678": responses.DESCRIBE_IMAGE_NOT_FOUND,
            }[kwargs["ImageIds"][0]]
        ),
    )
    assert AwsEC2Client(boto_mock, account()).list_instances() == responses.EXPECTED_INSTANCES_MISSING_IMAGE_DATA
