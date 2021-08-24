from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_iam_types import Role
from src.aws_scanner_config import AwsScannerConfig as Config


class AwsVpcClient:
    def __init__(self, ec2: AwsEC2Client, iam: AwsIamClient, logs: AwsLogsClient):
        self.ec2 = ec2
        self.iam = iam
        self.logs = logs
        self.config = Config()

    def find_flow_log_delivery_role(self) -> Role:
        return self.iam.get_role(self.config.logs_vpc_log_group_delivery_role())

    def is_flow_log_delivery_role_compliant(self, role: Role) -> bool:
        return role.assume_policy == self.config.logs_vpc_log_group_delivery_role_assume_policy() and bool(
            [p for p in role.policies if p.document == self.config.logs_vpc_log_group_delivery_role_policy_document()]
        )
