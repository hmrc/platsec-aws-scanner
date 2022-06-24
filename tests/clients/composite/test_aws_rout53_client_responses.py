from typing import Dict, Any, Sequence
from src.data.aws_route53_types import (
    Route53_Zone,
)

from tests.test_types_generator import (
    query_log,
    key,
    log_group,
    query_log,
    role,
)

a_key = key()
log_role = role(arn=str(query_log().deliver_log_role_arn))
group = log_group(kms_key_id=a_key.id, kms_key=a_key)

EXPECTED_LIST_HOSTED_ZONES: Sequence[Route53_Zone] = [
            Route53_Zone(
                id="/hostedzone/AAAABBBBCCCCDD",
                name="public.aws.scanner.gov.uk.",
                PrivateZone="false",
                query_logs=[query_log(deliver_log_role_arn=None, deliver_log_role=None, log_group=group)],
            ),
            Route53_Zone(
                id="/hostedzone/EEEEFFFFGGGGHH",
                name="private.aws.scanner.gov.uk.",
                PrivateZone="true",
                query_logs=[query_log(deliver_log_role=log_role, log_group_name=None)]
            )
]

