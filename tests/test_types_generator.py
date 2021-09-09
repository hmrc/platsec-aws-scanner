from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from botocore.exceptions import ClientError

from src.aws_scanner_argument_parser import AwsScannerArguments
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_compliance_actions import (
    CreateVpcLogGroupAction,
    CreateFlowLogAction,
    CreateFlowLogDeliveryRoleAction,
    DeleteFlowLogAction,
    DeleteFlowLogDeliveryRoleAction,
    PutVpcLogGroupSubscriptionFilterAction,
)
from src.data.aws_ec2_types import FlowLog, Vpc
from src.data.aws_iam_types import Policy, Role
from src.data.aws_logs_types import LogGroup, SubscriptionFilter
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
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.tasks.aws_organizations_task import AwsOrganizationsTask
from src.tasks.aws_ssm_task import AwsSSMTask
from src.tasks.aws_s3_task import AwsS3Task
from src.tasks.aws_task import AwsTask
from src.tasks.aws_vpc_task import AwsVpcTask


def partition(year: int = 2020, month: int = 11, region: str = "eu") -> AwsAthenaDataPartition:
    return AwsAthenaDataPartition(year, month, region)


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


def vpc_task(account: Account = account(), description: str = "vpc_task", enforce: bool = True) -> AwsVpcTask:
    return AwsVpcTask(description=description, account=account, enforce=enforce)


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


def aws_scanner_arguments(
    username: str = "bob",
    mfa_token: str = "123456",
    task: str = "a_task",
    year: int = 2020,
    month: int = 11,
    region: str = "eu",
    accounts: Optional[List[str]] = None,
    service: str = "a_service",
    role: str = "a_role",
    source_ip: str = "127.0.0.1",
    log_level: str = "ERROR",
    enforce: bool = False,
) -> AwsScannerArguments:
    return AwsScannerArguments(
        username=username,
        mfa_token=mfa_token,
        task=task,
        year=year,
        month=month,
        region=region,
        accounts=accounts if accounts is not None else ["999888777666", "555444333222"],
        service=service,
        role=role,
        source_ip=source_ip,
        log_level=log_level,
        enforce=enforce,
    )


def vpc(id: str = "vpc-1234", flow_logs: Optional[List[FlowLog]] = None) -> Vpc:
    return Vpc(id=id, flow_logs=flow_logs if flow_logs is not None else [flow_log(id="fl-1234")])


def policy(
    name: str = "a_policy",
    arn: str = "arn:aws:iam::112233445566:policy/a_policy",
    default_version: str = "v3",
    document: Optional[Dict[str, Any]] = None,
) -> Policy:
    return Policy(
        name=name,
        arn=arn,
        default_version=default_version,
        document=document,
    )


def role(
    name: str = "vpc_flow_log_role",
    arn: str = "arn:aws:iam::112233445566:role/a_role",
    assume_policy: Optional[Dict[str, Any]] = None,
    policies: Optional[Sequence[Policy]] = None,
) -> Role:
    return Role(
        name=name,
        arn=arn,
        assume_policy=assume_policy if assume_policy is not None else {"Statement": [{"Action": "sts:AssumeRole"}]},
        policies=policies
        if policies is not None
        else [
            policy(
                name="vpc_flow_log_role_policy",
                arn="arn:vpc_flow_log_role_policy",
                document={"Statement": [{"Effect": "Allow", "Action": ["logs:PutLogEvents"]}]},
            )
        ],
    )


def flow_log(
    id: str = "fl-1234",
    status: str = "ACTIVE",
    log_group_name: Optional[str] = "/vpc/flow_log",
    traffic_type: str = "ALL",
    log_format: str = "${srcaddr} ${dstaddr}",
    deliver_log_role_arn: Optional[str] = ":role/vpc_flow_log_role",
    deliver_log_role: Optional[Role] = role(name="vpc_flow_log_role"),
) -> FlowLog:
    return FlowLog(
        id=id,
        status=status,
        log_group_name=log_group_name,
        traffic_type=traffic_type,
        log_format=log_format,
        deliver_log_role_arn=deliver_log_role_arn,
        deliver_log_role=deliver_log_role,
    )


def create_flow_log_action(
    vpc_id: str = vpc().id,
    log_group_name: str = "/vpc/flow_log",
    permission_resolver: Callable[[], str] = lambda: "arn:aws:iam::112233445566:role/a_role",
) -> CreateFlowLogAction:
    return CreateFlowLogAction(vpc_id=vpc_id, log_group_name=log_group_name, permission_resolver=permission_resolver)


def delete_flow_log_action(flow_log_id: str = flow_log().id) -> DeleteFlowLogAction:
    return DeleteFlowLogAction(flow_log_id=flow_log_id)


def create_flow_log_delivery_role_action() -> CreateFlowLogDeliveryRoleAction:
    return CreateFlowLogDeliveryRoleAction()


def delete_flow_log_delivery_role_action() -> DeleteFlowLogDeliveryRoleAction:
    return DeleteFlowLogDeliveryRoleAction()


def create_vpc_log_group_action() -> CreateVpcLogGroupAction:
    return CreateVpcLogGroupAction()


def put_vpc_log_group_subscription_filter_action() -> PutVpcLogGroupSubscriptionFilterAction:
    return PutVpcLogGroupSubscriptionFilterAction()


def aws_audit_vpc_flow_logs_task(account: Account = account(), enforce: bool = False) -> AwsAuditVPCFlowLogsTask:
    return AwsAuditVPCFlowLogsTask(account=account, enforce=enforce)


def log_group(
    name: str = "/vpc/flow_log", subscription_filters: Optional[Sequence[SubscriptionFilter]] = None
) -> LogGroup:
    return LogGroup(
        name=name,
        subscription_filters=subscription_filters if subscription_filters is not None else [subscription_filter()],
    )


def subscription_filter(
    log_group_name: str = "/vpc/central_flow_log",
    filter_name: str = "VpcFlowLogsForward",
    filter_pattern: str = "[version, account_id, interface_id]",
    destination_arn: str = "arn:aws:logs:::destination:central",
) -> SubscriptionFilter:
    return SubscriptionFilter(
        log_group_name=log_group_name,
        filter_name=filter_name,
        filter_pattern=filter_pattern,
        destination_arn=destination_arn,
    )
