from logging import getLogger
from typing import Any, Sequence, List, Optional, Dict
from itertools import chain

import src.data.aws_route53_types as route53Type
from src.aws_scanner_config import AwsScannerConfig as Config

from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.aws_hosted_zones_client import AwsHostedZonesClient
from src.data.aws_organizations_types import Account

from src.data.aws_compliance_actions import (
    ComplianceAction,
    PutLogGroupRetentionPolicyAction,
    TagRoute53LogGroupAction,
    CreateLogGroupAction,
    DeleteQueryLogAction,
    CreateQueryLogAction,
)

from src.data.aws_logs_types import LogGroup
from src.data.aws_common_types import ServiceName


class AwsRoute53Client:
    def __init__(
        self,
        boto_route53: AwsHostedZonesClient,
        iam: AwsIamClient,
        logs: AwsLogsClient,
        kms: AwsKmsClient,
        config: Config,
    ):
        self._logger = getLogger(self.__class__.__name__)
        self._config = config
        self._route53 = boto_route53
        self._iam = iam
        self._logs = logs
        self.kms = kms

    def enforcement_actions(
        self, account: Account, hostedZones: Dict[Any, Any], with_subscription_filter: bool
    ) -> Sequence[ComplianceAction]:
        if not hostedZones:
            return list()
        log_group_actions = self._route53_log_group_enforcement_actions(with_subscription_filter)
        route53_actions = [
            action
            for zone in hostedZones
            for action in self._route53_enforcement_actions(account=account, hostedZone=hostedZones[zone])
        ]
        return list(chain(log_group_actions, route53_actions))

    def _route53_enforcement_actions(
        self, account: Account, hostedZone: route53Type.Route53Zone
    ) -> Sequence[ComplianceAction]:
        return list(
            chain(
                self._delete_misconfigured_query_log_actions(account, hostedZone),
                self._create_query_log_actions(account, hostedZone),
            )
        )

    def _delete_misconfigured_query_log_actions(
        self, account: Account, hostedZone: route53Type.Route53Zone
    ) -> Sequence[ComplianceAction]:

        query_log_arn = (
            "arn:aws:logs:us-east-1:"
            + account.identifier
            + ":log-group:"
            + self._config.logs_group_name(ServiceName.route53)
        )
        queryLogActionList = []

        if hostedZone.queryLog != query_log_arn:
            queryLogActionList.append(
                DeleteQueryLogAction(hosted_zone_id=hostedZone.id, route53_client=self._route53, config=self._config)
            )

        return queryLogActionList

    def _create_query_log_actions(
        self, account: Account, hostedZone: route53Type.Route53Zone
    ) -> Sequence[ComplianceAction]:
        queryLogActionList = []
        queryLogActionList.append(CreateQueryLogAction(account, self._route53, self._iam, self._config, hostedZone.id))
        return queryLogActionList

    def _route53_log_group_enforcement_actions(self, with_subscription_filter: bool) -> Sequence[ComplianceAction]:
        log_group = self._find_log_group(self._config.logs_group_name(ServiceName.route53))
        if log_group is not None:
            return [
                PutLogGroupRetentionPolicyAction(
                    logs=self._logs, config=self._config, service_name=ServiceName.route53
                ),
                TagRoute53LogGroupAction(logs=self._logs, config=self._config),
            ]
        actions: List[Any] = []

        actions.extend(
            [
                CreateLogGroupAction(logs=self._logs, config=self._config, service_name=ServiceName.route53),
                PutLogGroupRetentionPolicyAction(
                    logs=self._logs, config=self._config, service_name=ServiceName.route53
                ),
                TagRoute53LogGroupAction(logs=self._logs, config=self._config),
            ]
        )

        return actions

    def _find_log_group(self, name: str) -> Optional[LogGroup]:
        log_group = next(iter(self._logs.describe_log_groups(name)), None)
        kms_key = self.kms.get_key(log_group.kms_key_id) if log_group and log_group.kms_key_id else None
        return log_group.with_kms_key(kms_key) if log_group else None
