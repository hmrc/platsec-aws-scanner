from tests.aws_scanner_test_case import AwsScannerTestCase

from tests.test_types_generator import log_group, subscription_filter


class TestAwsLogsTypes(AwsScannerTestCase):
    def test_central_vpc_log_group(self) -> None:
        self.assertTrue(
            log_group(
                name="/vpc/central_flow_log_5678",
                subscription_filters=[
                    subscription_filter(
                        filter_pattern="[version, account_id, interface_id]",
                        destination_arn="arn:aws:logs:::destination:central",
                    )
                ],
            ).central_vpc_log_group
        )

    def test_log_group_is_not_vpc_central(self) -> None:
        self.assertFalse(log_group(name="/vpc/something_else").central_vpc_log_group)
        self.assertFalse(log_group(subscription_filters=[]).central_vpc_log_group)
        self.assertFalse(
            log_group(subscription_filters=[subscription_filter(filter_pattern="something")]).central_vpc_log_group
        )
        self.assertFalse(
            log_group(subscription_filters=[subscription_filter(destination_arn="somewhere")]).central_vpc_log_group
        )
