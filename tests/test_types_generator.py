from typing import Any, Dict, List, Optional, Sequence, Union
from unittest.mock import Mock

from botocore.exceptions import ClientError

from src import PLATSEC_SCANNER_TAGS
from src.aws_scanner_argument_parser import AwsScannerArguments
from src.aws_scanner_config import AwsScannerConfig
from src.clients.aws_iam_client import AwsIamClient
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_logs_client import AwsLogsClient
from src.data.aws_athena_data_partition import AwsAthenaDataPartition
from src.data.aws_common_types import Tag
from src.data.aws_compliance_actions import (
    ComplianceActionReport,
    CreateVpcLogGroupAction,
    CreateFlowLogAction,
    CreateFlowLogDeliveryRoleAction,
    DeleteFlowLogAction,
    DeleteFlowLogDeliveryRoleAction,
    DeleteVpcLogGroupSubscriptionFilterAction,
    PutVpcLogGroupRetentionPolicyAction,
    PutVpcLogGroupSubscriptionFilterAction,
    TagFlowLogDeliveryRoleAction,
    TagVpcLogGroupAction,
    UpdatePasswordPolicyAction,
)
from src.data.aws_ec2_types import FlowLog, Instance, Vpc, VpcPeeringConnection
from src.data.aws_iam_types import PasswordPolicy, Policy, Role
from src.data.aws_kms_types import Key
from src.data.aws_cloudtrail_types import DataResource, EventSelector, Trail
from src.data.aws_logs_types import LogGroup, SubscriptionFilter
from src.data.aws_organizations_types import Account, OrganizationalUnit
from src.data.aws_s3_types import (
    Bucket,
    BucketACL,
    BucketCompliancy,
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
    ComplianceCheck,
)
from src.data.aws_ssm_types import Parameter
from src.data.aws_task_report import AwsTaskReport
from src.tasks.aws_athena_task import AwsAthenaTask
from src.tasks.aws_audit_central_logging_task import AwsAuditCentralLoggingTask
from src.tasks.aws_audit_cost_explorer_task import AwsAuditCostExplorerTask
from src.tasks.aws_audit_cloudtrail_task import AwsAuditCloudtrailTask
from src.tasks.aws_audit_ec2_instances_task import AwsAuditEc2InstancesTask
from src.tasks.aws_audit_iam_task import AwsAuditIamTask
from src.tasks.aws_audit_password_policy_task import AwsAuditPasswordPolicyTask
from src.tasks.aws_audit_vpc_flow_logs_task import AwsAuditVPCFlowLogsTask
from src.tasks.aws_audit_vpc_peering_task import AwsAuditVpcPeeringTask
from src.tasks.aws_cloudtrail_task import AwsCloudTrailTask
from src.tasks.aws_create_flow_logs_table_task import AwsCreateFlowLogsTableTask
from src.tasks.aws_organizations_task import AwsOrganizationsTask
from src.tasks.aws_ssm_task import AwsSSMTask
from src.tasks.aws_s3_task import AwsS3Task
from src.tasks.aws_task import AwsTask


def partition(
    year: int = 2020, month: int = 11, region: str = "eu", day: Optional[int] = None
) -> AwsAthenaDataPartition:
    return AwsAthenaDataPartition(region, year, month, day)


def account(identifier: str = "account_id", name: str = "account_name") -> Account:
    return Account(identifier=identifier, name=name)


def organizational_unit(
    identifier: str, name: str, accounts: List[Account], org_units: List[OrganizationalUnit], root: bool = False
) -> OrganizationalUnit:
    return OrganizationalUnit(identifier=identifier, name=name, root=root, accounts=accounts, org_units=org_units)


def aws_task(account: Account = account(), description: str = "task") -> AwsTask:
    return AwsTask(description=description, account=account)


def athena_task(
    account: Account = account(), description: str = "athena_task", partition: AwsAthenaDataPartition = partition()
) -> AwsAthenaTask:
    return AwsAthenaTask(description=description, account=account, partition=partition)


def vpc_flow_logs_task(
    account: Account = account(), enforce: bool = True, with_subscription_filter: bool = False
) -> AwsAuditVPCFlowLogsTask:
    return AwsAuditVPCFlowLogsTask(account=account, enforce=enforce, with_subscription_filter=with_subscription_filter)


def s3_task(account: Account = account(), description: str = "s3_task") -> AwsS3Task:
    return AwsS3Task(description=description, account=account)


def ssm_task(account: Account = account(), description: str = "ssm_task") -> AwsSSMTask:
    return AwsSSMTask(description=description, account=account)


def organizations_task(account: Account = account(), description: str = "org_task") -> AwsOrganizationsTask:
    return AwsOrganizationsTask(description=description, account=account)


def cost_explorer_task(
    account: Account = account(), service: str = "bla", year: int = 2021, month: int = 4
) -> AwsAuditCostExplorerTask:
    return AwsAuditCostExplorerTask(account=account, service=service, year=year, month=month)


def cloudtrail_task(
    account: Account = account(), description: str = "task", partition: AwsAthenaDataPartition = partition()
) -> AwsCloudTrailTask:
    return AwsCloudTrailTask(description=description, account=account, partition=partition)


def audit_cloudtrail_task(account: Account = account()) -> AwsAuditCloudtrailTask:
    return AwsAuditCloudtrailTask(account=account)


def audit_iam_task(account: Account = account()) -> AwsAuditIamTask:
    return AwsAuditIamTask(account=account)


def audit_password_policy_task(account: Account = account(), enforce: bool = False) -> AwsAuditPasswordPolicyTask:
    return AwsAuditPasswordPolicyTask(account=account, enforce=enforce)


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
    return BucketACL(
        all_users_enabled=all_users_enabled,
        authenticated_users_enabled=authenticated_users_enabled,
    )


def bucket_compliancy(
    content_deny: bool = False,
    acl: bool = False,
    encryption: bool = False,
    logging: bool = False,
    public_access_block: bool = False,
    secure_transport: bool = False,
    versioning: bool = False,
    mfa_delete: bool = False,
    kms_key: bool = False,
    tagging: bool = False,
    lifecycle: bool = False,
    cors: bool = False,
) -> BucketCompliancy:
    return BucketCompliancy(
        content_deny=ComplianceCheck(
            compliant=content_deny, message="bucket should have a resource policy with a default deny action"
        ),
        acl=ComplianceCheck(compliant=acl, message="bucket should not have ACL set"),
        encryption=ComplianceCheck(compliant=encryption, message="bucket should be encrypted"),
        logging=ComplianceCheck(compliant=logging, message="bucket should have logging enabled"),
        public_access_block=ComplianceCheck(
            compliant=public_access_block, message="bucket should not allow public access"
        ),
        secure_transport=ComplianceCheck(
            compliant=secure_transport, message="bucket should have a resource policy with secure transport enforced"
        ),
        versioning=ComplianceCheck(compliant=versioning, message="bucket should have versioning enabled"),
        mfa_delete=ComplianceCheck(compliant=mfa_delete, message="MFA delete should be disabled"),
        kms_key=ComplianceCheck(compliant=kms_key, message="bucket kms key should have rotation enabled"),
        tagging=ComplianceCheck(compliant=tagging, message="bucket should have tags for expiry and sensitivity"),
        lifecycle=ComplianceCheck(
            compliant=lifecycle, message="bucket should have a lifecycle configuration set for current/previous version"
        ),
        cors=ComplianceCheck(compliant=cors, message="bucket should not have CORS set"),
    )


def bucket_content_deny(enabled: bool = False) -> BucketContentDeny:
    return BucketContentDeny(enabled=enabled)


def bucket_cors(enabled: bool = True) -> BucketCORS:
    return BucketCORS(enabled=enabled)


def bucket_data_tagging(expiry: str = "unset", sensitivity: str = "unset") -> BucketDataTagging:
    return BucketDataTagging(expiry=expiry, sensitivity=sensitivity)


def bucket_encryption(
    enabled: bool = False, key_id: Optional[str] = None, type: Optional[str] = None
) -> BucketEncryption:
    return BucketEncryption(enabled=enabled, key_id=key_id, type=type)


def bucket_lifecycle(
    current_version_expiry: Union[int, str] = "unset",
    previous_version_deletion: Union[int, str] = "unset",
) -> BucketLifecycle:
    return BucketLifecycle(
        current_version_expiry=current_version_expiry,
        previous_version_deletion=previous_version_deletion,
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
    compliancy: Optional[BucketCompliancy] = None,
    acl: Optional[BucketACL] = None,
    content_deny: Optional[BucketContentDeny] = None,
    cors: Optional[BucketCORS] = None,
    data_tagging: Optional[BucketDataTagging] = None,
    encryption: Optional[BucketEncryption] = None,
    kms_key: Optional[Key] = None,
    lifecycle: Optional[BucketLifecycle] = None,
    logging: Optional[BucketLogging] = None,
    mfa_delete: Optional[BucketMFADelete] = None,
    public_access_block: Optional[BucketPublicAccessBlock] = None,
    secure_transport: Optional[BucketSecureTransport] = None,
    versioning: Optional[BucketVersioning] = None,
    policy: Optional[Dict[str, Any]] = None,
) -> Bucket:
    return Bucket(
        name=name,
        compliancy=compliancy,
        acl=acl,
        content_deny=content_deny,
        cors=cors,
        data_tagging=data_tagging,
        encryption=encryption,
        kms_key=kms_key,
        lifecycle=lifecycle,
        logging=logging,
        mfa_delete=mfa_delete,
        public_access_block=public_access_block,
        secure_transport=secure_transport,
        versioning=versioning,
        policy=policy,
    )


def aws_scanner_arguments(
    username: str = "bob",
    mfa_token: str = "123456",
    task: str = "a_task",
    year: int = 2020,
    month: int = 11,
    region: str = "eu",
    accounts: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    role: str = "a_role",
    source_ip: str = "127.0.0.1",
    log_level: str = "ERROR",
    enforce: bool = False,
    disable_account_lookup: bool = False,
    with_subscription_filter: bool = False,
    parent: str = "Parent OU",
    day: Optional[int] = None,
) -> AwsScannerArguments:
    return AwsScannerArguments(
        username=username,
        mfa_token=mfa_token,
        task=task,
        year=year,
        month=month,
        region=region,
        accounts=accounts if accounts is not None else ["999888777666", "555444333222"],
        services=services or ["a_service"],
        role=role,
        source_ip=source_ip,
        log_level=log_level,
        enforce=enforce,
        disable_account_lookup=disable_account_lookup,
        with_subscription_filter=with_subscription_filter,
        parent=parent,
        day=day,
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
    tags: Optional[Sequence[Tag]] = PLATSEC_SCANNER_TAGS,
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
                document={"Statement": [{"Effect": "Allow", "Action": ["logs:*"], "Resource": "*"}]},
            )
        ],
        tags=tags,
    )


def flow_log(
    id: str = "fl-1234",
    status: str = "ACTIVE",
    log_destination: Optional[str] = "arn:/vpc/flow_log",
    log_destination_type: Optional[str] = "cloud-watch-logs",
    log_group_name: Optional[str] = "/vpc/flow_log",
    traffic_type: str = "ALL",
    log_format: str = "${srcaddr} ${dstaddr}",
    deliver_log_role_arn: Optional[str] = ":role/vpc_flow_log_role",
    deliver_log_role: Optional[Role] = role(name="vpc_flow_log_role"),
    log_group: Optional[LogGroup] = None,
) -> FlowLog:
    return FlowLog(
        id=id,
        status=status,
        log_destination=log_destination,
        log_destination_type=log_destination_type,
        log_group_name=log_group_name,
        traffic_type=traffic_type,
        log_format=log_format,
        deliver_log_role_arn=deliver_log_role_arn,
        deliver_log_role=deliver_log_role,
        log_group=log_group,
    )


def create_flow_log_action(
    ec2_client: AwsEC2Client = Mock(spec=AwsEC2Client),
    iam: AwsIamClient = Mock(spec=AwsIamClient),
    vpc_id: str = vpc().id,
) -> CreateFlowLogAction:
    return CreateFlowLogAction(ec2_client=ec2_client, iam=iam, config=AwsScannerConfig(), vpc_id=vpc_id)


def delete_flow_log_action(
    ec2_client: AwsEC2Client = Mock(spec=AwsEC2Client), flow_log_id: str = flow_log().id
) -> DeleteFlowLogAction:
    return DeleteFlowLogAction(ec2_client=ec2_client, flow_log_id=flow_log_id)


def create_flow_log_delivery_role_action(
    iam: AwsIamClient = Mock(spec=AwsIamClient),
) -> CreateFlowLogDeliveryRoleAction:
    return CreateFlowLogDeliveryRoleAction(iam=iam)


def delete_flow_log_delivery_role_action(iam: AwsIamClient = Mock(AwsIamClient)) -> DeleteFlowLogDeliveryRoleAction:
    return DeleteFlowLogDeliveryRoleAction(iam=iam)


def create_vpc_log_group_action(logs: AwsLogsClient = Mock(spec=AwsLogsClient)) -> CreateVpcLogGroupAction:
    return CreateVpcLogGroupAction(logs=logs)


def put_vpc_log_group_subscription_filter_action(
    logs: AwsLogsClient = Mock(spec=AwsLogsClient),
) -> PutVpcLogGroupSubscriptionFilterAction:
    return PutVpcLogGroupSubscriptionFilterAction(logs=logs)


def delete_vpc_log_group_subscription_filter_action(
    logs: AwsLogsClient = Mock(spec=AwsLogsClient),
) -> DeleteVpcLogGroupSubscriptionFilterAction:
    return DeleteVpcLogGroupSubscriptionFilterAction(logs=logs)


def put_vpc_log_group_retention_policy_action(
    logs: AwsLogsClient = Mock(spec=AwsLogsClient),
) -> PutVpcLogGroupRetentionPolicyAction:
    return PutVpcLogGroupRetentionPolicyAction(logs=logs)


def tag_flow_log_delivery_role_action(iam: AwsIamClient = Mock(spec=AwsIamClient)) -> TagFlowLogDeliveryRoleAction:
    return TagFlowLogDeliveryRoleAction(iam=iam)


def tag_vpc_log_group_action(
    logs: AwsLogsClient = Mock(spec=AwsLogsClient),
) -> TagVpcLogGroupAction:
    return TagVpcLogGroupAction(logs=logs)


def update_password_policy_action(iam: AwsIamClient = Mock(spec=AwsIamClient)) -> UpdatePasswordPolicyAction:
    return UpdatePasswordPolicyAction(iam=iam)


def aws_audit_vpc_flow_logs_task(
    account: Account = account(), enforce: bool = False, with_subscription_filter: bool = False
) -> AwsAuditVPCFlowLogsTask:
    return AwsAuditVPCFlowLogsTask(account=account, enforce=enforce, with_subscription_filter=with_subscription_filter)


def log_group(
    name: str = "/vpc/flow_log",
    kms_key_id: Optional[str] = None,
    kms_key: Optional[Key] = None,
    retention_days: Optional[int] = 14,
    stored_bytes: Optional[int] = None,
    subscription_filters: Optional[Sequence[SubscriptionFilter]] = None,
    tags: Optional[Sequence[Tag]] = PLATSEC_SCANNER_TAGS,
    default_kms_key: bool = False,
) -> LogGroup:
    if default_kms_key:
        kms_key_id = key().id
        kms_key = key()
    return LogGroup(
        name=name,
        kms_key_id=kms_key_id,
        kms_key=kms_key,
        retention_days=retention_days,
        stored_bytes=stored_bytes,
        subscription_filters=subscription_filters if subscription_filters is not None else [subscription_filter()],
        tags=tags,
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


def key(
    account_id: str = "112233445566",
    region: str = "us-east-1",
    id: str = "1234abcd",
    arn: str = "arn:aws:kms:us-east-1:112233445566:key/1234abcd",
    description: str = "some key desc",
    state: str = "Enabled",
    rotation_enabled: bool = True,
    policy: Optional[Dict[str, Any]] = None,
    with_default_tags: bool = False,
    tags: Optional[Sequence[Tag]] = None,
) -> Key:
    tags = PLATSEC_SCANNER_TAGS if with_default_tags else tags
    return Key(
        account_id=account_id,
        region=region,
        id=id,
        arn=arn,
        description=description,
        state=state,
        rotation_enabled=rotation_enabled,
        policy=policy,
        tags=tags,
    )


def compliance_action_report(
    description: Optional[str] = None, status: Optional[str] = None, details: Optional[Dict[str, Any]] = None
) -> ComplianceActionReport:
    return ComplianceActionReport(status=status, description=description, details=details or dict())


def tag(key: str, value: str) -> Tag:
    return Tag(key=key, value=value)


def password_policy(
    minimum_password_length: Optional[int] = 8,
    require_symbols: Optional[bool] = True,
    require_numbers: Optional[bool] = True,
    require_uppercase_chars: Optional[bool] = False,
    require_lowercase_chars: Optional[bool] = False,
    allow_users_to_change_password: Optional[bool] = False,
    expire_passwords: Optional[bool] = True,
    max_password_age: Optional[int] = 90,
    password_reuse_prevention: Optional[int] = 12,
    hard_expiry: Optional[bool] = False,
) -> PasswordPolicy:
    return PasswordPolicy(
        minimum_password_length=minimum_password_length,
        require_symbols=require_symbols,
        require_numbers=require_numbers,
        require_uppercase_chars=require_uppercase_chars,
        require_lowercase_chars=require_lowercase_chars,
        allow_users_to_change_password=allow_users_to_change_password,
        expire_passwords=expire_passwords,
        max_password_age=max_password_age,
        password_reuse_prevention=password_reuse_prevention,
        hard_expiry=hard_expiry,
    )


def trail(
    name: str = "a_trail",
    s3_bucket_name: str = "a_bucket",
    is_logging: bool = False,
    is_multiregion_trail: bool = False,
    kms_key_id: str = "998877",
    log_file_validation_enabled: bool = False,
    include_global_service_events: bool = False,
    event_selectors: Optional[Sequence[EventSelector]] = None,
) -> Trail:
    return Trail(
        name=name,
        s3_bucket_name=s3_bucket_name,
        is_logging=is_logging,
        is_multiregion_trail=is_multiregion_trail,
        kms_key_id=kms_key_id,
        log_file_validation_enabled=log_file_validation_enabled,
        include_global_service_events=include_global_service_events,
        event_selectors=event_selectors or [],
    )


def data_resource(type: str = "some_type", values: Optional[Sequence[str]] = None) -> DataResource:
    return DataResource(type=type, values=values or [])


def event_selector(
    read_write_type: str = "ALL",
    include_management_events: bool = False,
    data_resources: Optional[Sequence[DataResource]] = None,
) -> EventSelector:
    return EventSelector(
        read_write_type=read_write_type,
        include_management_events=include_management_events,
        data_resources=data_resources or [],
    )


def audit_central_logging_task() -> AwsAuditCentralLoggingTask:
    return AwsAuditCentralLoggingTask()


def create_flow_logs_table_task(partition: AwsAthenaDataPartition = partition()) -> AwsCreateFlowLogsTableTask:
    return AwsCreateFlowLogsTableTask(partition=partition)


def vpc_peering_connection(
    id: str = "pcx-1234",
    accepter_owner_id: str = "1234",
    accepter_vpc_id: str = "vpc-1",
    requester_owner_id: str = "5678",
    requester_vpc_id: str = "vpc-2",
    status: str = "active",
    accepter: Optional[Account] = None,
    requester: Optional[Account] = None,
) -> VpcPeeringConnection:
    return VpcPeeringConnection(
        id=id,
        accepter_owner_id=accepter_owner_id,
        accepter_vpc_id=accepter_vpc_id,
        requester_owner_id=requester_owner_id,
        requester_vpc_id=requester_vpc_id,
        status=status,
        accepter=accepter,
        requester=requester,
    )


def audit_vpc_peering_task(account: Account = account()) -> AwsAuditVpcPeeringTask:
    return AwsAuditVpcPeeringTask(account)


def audit_ec2_instances_task(account: Account = account()) -> AwsAuditEc2InstancesTask:
    return AwsAuditEc2InstancesTask(account)


def instance(
    id: str = "instance-1234",
    component: str = "some-component",
    image_id: str = "image-5678",
    image_creation_date: str = "2020-03-23T09:01:26.000Z",
    launch_time: str = "2020-03-25T09:06:07+00:00",
    metadata_options_http_tokens: str = "required",
) -> Instance:
    return Instance(
        id=id,
        component=component,
        image_id=image_id,
        image_creation_date=image_creation_date,
        launch_time=launch_time,
        metadata_options_http_tokens=metadata_options_http_tokens,
    )
