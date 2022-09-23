
from logging import getLogger
from typing import  Optional, Sequence, List, Any

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import LogGroupConfig
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import (
    ComplianceAction,
    CreateLogGroupAction,
    DeleteLogGroupSubscriptionFilterAction,
    PutLogGroupSubscriptionFilterAction,
    PutLogGroupRetentionPolicyAction,
    TagLogGroupAction,
)
from src.data.aws_logs_types import LogGroup


class AwsLogGroupClient:
     def __init__(self, logs: AwsLogsClient, kms: AwsKmsClient):
        self.kms = kms
        self.logs = logs
        
     def log_group_enforcement_actions(self, log_group_config: LogGroupConfig, with_subscription_filter: bool) -> Sequence[ComplianceAction]:
        log_group = self.find_log_group(log_group_config.logs_group_name)
        actions: List[Any] = []
        if log_group:
            if (
                self.logs.is_central_log_group(log_group=log_group, log_group_config=log_group_config)
                and not with_subscription_filter
            ):
                actions.append(
                    DeleteLogGroupSubscriptionFilterAction(
                        logs=self.logs, log_group_config=log_group_config
                    )
                )
            if (
                not self.logs.is_central_log_group(log_group=log_group, log_group_config=log_group_config)
                and with_subscription_filter
            ):
                actions.append(
                    PutLogGroupSubscriptionFilterAction(
                        logs=self.logs, log_group_config =log_group_config
                    )
                )
            if log_group.retention_days != log_group_config.logs_group_retention_policy_days:
                actions.append(
                    PutLogGroupRetentionPolicyAction(logs=self.logs, log_group_config=log_group_config)
                )
            if not set(PLATSEC_SCANNER_TAGS).issubset(log_group.tags):
                actions.append(TagLogGroupAction(logs=self.logs, log_group_config=log_group_config))
        else:
            actions.extend(
                [
                    CreateLogGroupAction(logs=self.logs, log_group_config =log_group_config),
                    PutLogGroupRetentionPolicyAction(logs=self.logs, log_group_config =log_group_config),
                    TagLogGroupAction(logs=self.logs, log_group_config =log_group_config),
                ]
            )
            if with_subscription_filter:
                actions.append(
                    PutLogGroupSubscriptionFilterAction(
                        logs=self.logs, log_group_config =log_group_config
                    )
                )

        return actions
    
     def find_log_group(self, name: str) -> Optional[LogGroup]:
        log_group = next(iter(self.logs.describe_log_groups(name)), None)
        kms_key = self.kms.get_key(log_group.kms_key_id) if log_group and log_group.kms_key_id else None
        return log_group.with_kms_key(kms_key) if log_group else None
    