from unittest.mock import patch

from datetime import date
from typing import Any, Dict, List, Optional, Union

from botocore.exceptions import ClientError

from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_organizations_types import Account, OrganizationalUnit
from src.data.aws_s3_types import (
    Bucket,
    BucketACL,
    BucketContentDeny,
    BucketCORS,
    BucketDataTagging,
    BucketEncryption,
    BucketLifecycle,
    BucketLogging,
    BucketMFADelete,
    BucketPublicAccessBlock,
    BucketSecureTransport,
    BucketVersioning,
)
from src.data.aws_ssm_types import Parameter
from src.data.aws_task_report import AwsTaskReport
from src.tasks.aws_athena_task import AwsAthenaTask
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.tasks.aws_organizations_task import AwsOrganizationsTask
from src.tasks.aws_ssm_task import AwsSSMTask
from src.tasks.aws_s3_task import AwsS3Task
from src.tasks.aws_task import AwsTask


def partition(year: int = date.today().year, month: int = date.today().month) -> AwsAthenaDataPartition:
    with patch("src.data.aws_athena_data_partition.AwsAthenaDataPartition._today", return_value=date(year, month, 1)):
        return AwsAthenaDataPartition(year, month)


def account(identifier: str = "account_id", name: str = "account_name") -> Account:
    return Account(identifier=identifier, name=name)


def organizational_unit(
    identifier: str, name: str, accounts: List[Account], org_units: List[OrganizationalUnit], root: bool = False
) -> OrganizationalUnit:
    return OrganizationalUnit(identifier=identifier, name=name, root=root, accounts=accounts, org_units=org_units)


def aws_task(account: Account = account(), description: str = "task") -> AwsTask:
    return AwsTask(description=description, account=account)


def athena_task(account: Account = account(), description: str = "athena_task") -> AwsAthenaTask:
    return AwsAthenaTask(description=description, account=account)


def s3_task(account: Account = account(), description: str = "s3_task") -> AwsS3Task:
    return AwsS3Task(description=description, account=account)


def ssm_task(account: Account = account(), description: str = "ssm_task") -> AwsSSMTask:
    return AwsSSMTask(description=description, account=account)


def organizations_task(account: Account = account(), description: str = "org_task") -> AwsOrganizationsTask:
    return AwsOrganizationsTask(description=description, account=account)


def cloudtrail_task(
    account: Account = account(), description: str = "task", partition: AwsAthenaDataPartition = partition()
) -> AwsCloudTrailTask:
    return AwsCloudTrailTask(description=description, account=account, partition=partition)


def task_report(
    account: Account = account(),
    description: str = "task",
    partition: Optional[AwsAthenaDataPartition] = partition(),
    results: Dict[Any, Any] = {"key": "val"},
) -> AwsTaskReport:
    return AwsTaskReport(account, description, partition, results)


def secure_string_parameter(name: str) -> Parameter:
    return Parameter(name=name, type="SecureString")


def string_list_parameter(name: str) -> Parameter:
    return Parameter(name=name, type="StringList")


def string_parameter(name: str) -> Parameter:
    return Parameter(name=name, type="String")


def client_error(op_name: str, code: str, msg: str) -> ClientError:
    return ClientError(operation_name=op_name, error_response={"Error": {"Code": code, "Message": msg}})


def bucket_acl(all_users_enabled: bool = True, authenticated_users_enabled: bool = True) -> BucketACL:
    return BucketACL(all_users_enabled=all_users_enabled, authenticated_users_enabled=authenticated_users_enabled)


def bucket_content_deny(enabled: bool = False) -> BucketContentDeny:
    return BucketContentDeny(enabled=enabled)


def bucket_cors(enabled: bool = True) -> BucketCORS:
    return BucketCORS(enabled=enabled)


def bucket_data_tagging(expiry: str = "unset", sensitivity: str = "unset") -> BucketDataTagging:
    return BucketDataTagging(expiry=expiry, sensitivity=sensitivity)


def bucket_encryption(enabled: bool = False, type: Optional[str] = None) -> BucketEncryption:
    return BucketEncryption(enabled=enabled, type=type)


def bucket_lifecycle(
    current_version_expiry: Union[int, str] = "unset", previous_version_deletion: Union[int, str] = "unset"
) -> BucketLifecycle:
    return BucketLifecycle(
        current_version_expiry=current_version_expiry, previous_version_deletion=previous_version_deletion
    )


def bucket_logging(enabled: bool = False) -> BucketLogging:
    return BucketLogging(enabled=enabled)


def bucket_mfa_delete(enabled: bool = False) -> BucketMFADelete:
    return BucketMFADelete(enabled=enabled)


def bucket_public_access_block(enabled: bool = False) -> BucketPublicAccessBlock:
    return BucketPublicAccessBlock(enabled=enabled)


def bucket_secure_transport(enabled: bool = False) -> BucketSecureTransport:
    return BucketSecureTransport(enabled=enabled)


def bucket_versioning(enabled: bool = False) -> BucketVersioning:
    return BucketVersioning(enabled=enabled)


def bucket(
    name: str = "a_bucket",
    acl: Optional[BucketACL] = None,
    content_deny: Optional[BucketContentDeny] = None,
    cors: Optional[BucketCORS] = None,
    data_tagging: Optional[BucketDataTagging] = None,
    encryption: Optional[BucketEncryption] = None,
    lifecycle: Optional[BucketLifecycle] = None,
    logging: Optional[BucketLogging] = None,
    mfa_delete: Optional[BucketMFADelete] = None,
    public_access_block: Optional[BucketPublicAccessBlock] = None,
    secure_transport: Optional[BucketSecureTransport] = None,
    versioning: Optional[BucketVersioning] = None,
) -> Bucket:
    return Bucket(
        name=name,
        acl=acl,
        content_deny=content_deny,
        cors=cors,
        data_tagging=data_tagging,
        encryption=encryption,
        lifecycle=lifecycle,
        logging=logging,
        mfa_delete=mfa_delete,
        public_access_block=public_access_block,
        secure_transport=secure_transport,
        versioning=versioning,
    )
