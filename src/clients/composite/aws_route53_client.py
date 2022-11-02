from logging import getLogger
from typing import Any, List, Sequence, Dict
from itertools import chain
from src.clients.aws_log_group_client import AwsLogGroupClient

import src.data.aws_route53_types as route53Type
from src.aws_scanner_config import AwsScannerConfig as Config

from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_hosted_zones_client import AwsHostedZonesClient
from src.data.aws_organizations_types import Account

from src.data.aws_compliance_actions import (
    ComplianceAction,
    DeleteQueryLogAction,
    CreateQueryLogAction,
)


class AwsRoute53Client:
    def __init__(self, boto_route53: AwsHostedZonesClient, iam: AwsIamClient, log_group: AwsLogGroupClient):
        self._logger = getLogger(self.__class__.__name__)
        self._route53 = boto_route53
        self._iam = iam
        self.log_group = log_group
        self.log_group_config = Config().route53_query_log_config()

    def enforcement_actions(
        self, account: Account, hostedZones: Dict[Any, Any], with_subscription_filter: bool, skip_tags: bool
    ) -> Sequence[ComplianceAction]:
        if not hostedZones:
            return list()

        log_group_actions: List[ComplianceAction] = self.log_group.log_group_enforcement_actions(
            log_group_config=self.log_group_config,
            with_subscription_filter=with_subscription_filter,
            skip_tags=skip_tags,
        )

        route53_actions: List[ComplianceAction] = [
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
            "arn:aws:logs:us-east-1:" + account.identifier + ":log-group:" + self.log_group_config.logs_group_name
        )
        queryLogActionList = []

        if hostedZone.queryLog != query_log_arn:
            queryLogActionList.append(DeleteQueryLogAction(hosted_zone_id=hostedZone.id, route53_client=self._route53))

        return queryLogActionList

    def _create_query_log_actions(
        self, account: Account, hostedZone: route53Type.Route53Zone
    ) -> Sequence[ComplianceAction]:
        queryLogActionList = []
        hosted_zone_query_log = self._route53.list_query_logging_configs(id=hostedZone.id)
        if (
            len(hosted_zone_query_log["QueryLoggingConfigs"]) == 0
            or hosted_zone_query_log["QueryLoggingConfigs"][0]["CloudWatchLogsLogGroupArn"] == ""
        ):
            queryLogActionList.append(
                CreateQueryLogAction(
                    account=account,
                    route53_client=self._route53,
                    iam=self._iam,
                    log_group_config=self.log_group_config,
                    zone_id=hostedZone.id,
                )
            )
        return queryLogActionList
