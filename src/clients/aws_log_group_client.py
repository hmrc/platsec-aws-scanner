from typing import List, Any

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_config import LogGroupConfig
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_compliance_actions import (
    ComplianceAction,
    CreateLogGroupAction,
    DeleteLogGroupSubscriptionFilterAction,
    PutLogGroupSubscriptionFilterAction,
    PutLogGroupRetentionPolicyAction,
    TagLogGroupAction,
)


class AwsLogGroupClient:
    def __init__(self, logs: AwsLogsClient):
        self.logs = logs

    def log_group_enforcement_actions(
        self, log_group_config: LogGroupConfig, with_subscription_filter: bool
    ) -> List[ComplianceAction]:

        log_group = self.logs.find_log_group(log_group_config.logs_group_name)

        actions: List[Any] = []

        if log_group:
            if (
                self.logs.is_central_log_group(log_group=log_group, log_group_config=log_group_config)
                and not with_subscription_filter
            ):
                actions.append(
                    DeleteLogGroupSubscriptionFilterAction(logs=self.logs, log_group_config=log_group_config)
                )
            if (
                not self.logs.is_central_log_group(log_group=log_group, log_group_config=log_group_config)
                and with_subscription_filter
            ):
                actions.append(PutLogGroupSubscriptionFilterAction(logs=self.logs, log_group_config=log_group_config))
            if log_group.retention_days != log_group_config.logs_group_retention_policy_days:
                actions.append(PutLogGroupRetentionPolicyAction(logs=self.logs, log_group_config=log_group_config))
            if not set(PLATSEC_SCANNER_TAGS).issubset(log_group.tags):
                actions.append(TagLogGroupAction(logs=self.logs, log_group_config=log_group_config))
        else:
            actions.extend(
                [
                    CreateLogGroupAction(logs=self.logs, log_group_config=log_group_config),
                    PutLogGroupRetentionPolicyAction(logs=self.logs, log_group_config=log_group_config),
                    TagLogGroupAction(logs=self.logs, log_group_config=log_group_config),
                ]
            )

            if with_subscription_filter:
                actions.append(PutLogGroupSubscriptionFilterAction(logs=self.logs, log_group_config=log_group_config))

        return actions
