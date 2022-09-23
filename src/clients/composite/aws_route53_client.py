from json import dumps
from logging import getLogger
from typing import Any, Sequence, List, Optional, Dict
from itertools import chain
from src.clients.aws_log_group_client import AwsLogGroupClient

import src.data.aws_route53_types as route53Type
from src.aws_scanner_config import AwsScannerConfig as Config

from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_kms_client import AwsKmsClient
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.aws_hosted_zones_client import AwsHostedZonesClient
from src.data.aws_organizations_types import Account

from src.data.aws_compliance_actions import (
    ComplianceAction,
    DeleteQueryLogAction,
    CreateQueryLogAction,
    PutRoute53LogGroupResourcePolicyAction,
)


class AwsRoute53Client:
    def __init__(
        self,
        boto_route53: AwsHostedZonesClient,
        iam: AwsIamClient,
        logs: AwsLogsClient,
        log_group: AwsLogGroupClient
    ):
        self._logger = getLogger(self.__class__.__name__)
        self._route53 = boto_route53
        self._iam = iam
        self._logs = logs
        self.log_group = log_group
        self.log_group_config = Config().logs_route53_query_log_group_config()

    def enforcement_actions(
        self, account: Account, hostedZones: Dict[Any, Any], with_subscription_filter: bool
    ) -> Sequence[ComplianceAction]:
        if not hostedZones:
            return list()
        
        policy_document = self._route53_query_logs_resource_policy_document(account)
        log_group_actions = self.log_group.log_group_enforcement_actions(
            log_group_config=self.log_group_config, with_subscription_filter=with_subscription_filter
        )
        log_group_actions.append(
            PutRoute53LogGroupResourcePolicyAction(
                logs=self._logs, log_group_config=self.log_group_config , policy_document=policy_document
            ))
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
            + self.log_group_config .logs_group_name
        )
        queryLogActionList = []

        if hostedZone.queryLog != query_log_arn:
            queryLogActionList.append(
                DeleteQueryLogAction(hosted_zone_id=hostedZone.id, route53_client=self._route53)
            )

        return queryLogActionList

    def _create_query_log_actions(
        self, account: Account, hostedZone: route53Type.Route53Zone
    ) -> Sequence[ComplianceAction]:
        queryLogActionList = []
        queryLogActionList.append(CreateQueryLogAction(account= account, route53_client= self._route53, iam =self._iam , log_group_config = self.log_group_config, zone_id=  hostedZone.id))
        return queryLogActionList

    def _route53_query_logs_resource_policy_document(self, account: Account) -> str:
        return dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {"Service": ["route53.amazonaws.com"]},
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:us-east-1:{account.identifier}:log-group:*",
                    }
                ],
            }
        )
