from tests.aws_scanner_test_case import AwsScannerTestCase
from unittest.mock import Mock

from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask

from tests.test_types_generator import account, flow_log, task_report, vpc


class TestAwsAuditVPCFlowLogsTask(AwsScannerTestCase):
    def test_run_task(self) -> None:
        task = AwsAuditVPCFlowLogsTask(account(), enforce=False)
        compliant_fl = flow_log()
        non_compliant_fl_1 = flow_log(id="non-compliant-1", status="DISABLED")
        non_compliant_fl_2 = flow_log(id="non-compliant-2", traffic_type="REJECT")
        non_compliant_fl_3 = flow_log(id="non-compliant-3", log_destination="arn:aws:s3:::another-bucket")
        non_compliant_fl_4 = flow_log(id="non-compliant-4", log_format="${something}")
        vpcs = [
            vpc(
                flow_logs=[compliant_fl, non_compliant_fl_1, non_compliant_fl_2, non_compliant_fl_3, non_compliant_fl_4]
            )
        ]
        ec2_client = Mock(list_vpcs=Mock(return_value=vpcs))
        vpcs_audit = task.run(ec2_client)

        report = task_report(
            account=account(),
            description="audit VPC flow logs compliance",
            partition=None,
            results={
                "vpcs": [
                    vpc(
                        id="vpc-1234",
                        flow_logs=[
                            flow_log(
                                id="fl-1234",
                                status="ACTIVE",
                                traffic_type="ALL",
                                log_destination="arn:aws:s3:::central-flow-logs-bucket",
                                log_format="${srcaddr} ${dstaddr}",
                            ),
                            flow_log(
                                id="non-compliant-1",
                                status="DISABLED",
                                traffic_type="ALL",
                                log_destination="arn:aws:s3:::central-flow-logs-bucket",
                                log_format="${srcaddr} ${dstaddr}",
                            ),
                            flow_log(
                                id="non-compliant-2",
                                status="ACTIVE",
                                traffic_type="REJECT",
                                log_destination="arn:aws:s3:::central-flow-logs-bucket",
                                log_format="${srcaddr} ${dstaddr}",
                            ),
                            flow_log(
                                id="non-compliant-3",
                                status="ACTIVE",
                                traffic_type="ALL",
                                log_destination="arn:aws:s3:::another-bucket",
                                log_format="${srcaddr} ${dstaddr}",
                            ),
                            flow_log(
                                id="non-compliant-4",
                                status="ACTIVE",
                                traffic_type="ALL",
                                log_destination="arn:aws:s3:::central-flow-logs-bucket",
                                log_format="${something}",
                            ),
                        ],
                    )
                ]
            },
        )

        self.assertEqual(report, vpcs_audit)
