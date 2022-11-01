from typing import Any, Dict

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_iam_client import AwsIamClient
from src.data.aws_compliance_actions import UpdatePasswordPolicyAction
from src.data.aws_organizations_types import Account
from src.tasks.aws_task import AwsTask


class AwsAuditPasswordPolicyTask(AwsTask):
    def __init__(self, account: Account, enforce: bool, region: str) -> None:
        super().__init__(
            description="audit password policy compliance",
            account=account,
            region=region,
        )
        self.enforce = enforce

    def _run_task(self, client: AwsIamClient) -> Dict[Any, Any]:
        reference_policy = Config().iam_password_policy()
        current_policy = client.get_account_password_policy()
        actions = [] if current_policy == reference_policy else [UpdatePasswordPolicyAction(iam=client)]
        action_reports = list(map(lambda a: a.apply() if self.enforce else a.plan(), actions))
        return {
            "password_policy": current_policy,
            "enforcement_actions": action_reports,
        }
