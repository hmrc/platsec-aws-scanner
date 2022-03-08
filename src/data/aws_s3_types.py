from __future__ import annotations
from dataclasses import dataclass
from json import loads
from typing import Any, Dict, List, Optional, Union
from src.data.aws_kms_types import Key


@dataclass
class Bucket:
    name: str
    acl: Optional[BucketACL] = None
    content_deny: Optional[BucketContentDeny] = None
    cors: Optional[BucketCORS] = None
    data_tagging: Optional[BucketDataTagging] = None
    encryption: Optional[BucketEncryption] = None
    kms_key: Optional[Key] = None
    lifecycle: Optional[BucketLifecycle] = None
    logging: Optional[BucketLogging] = None
    mfa_delete: Optional[BucketMFADelete] = None
    public_access_block: Optional[BucketPublicAccessBlock] = None
    secure_transport: Optional[BucketSecureTransport] = None
    versioning: Optional[BucketVersioning] = None
    policy: Optional[Dict[str, Any]] = None


def to_bucket(bucket_dict: Dict[Any, Any]) -> Bucket:
    return Bucket(name=bucket_dict["Name"])


@dataclass
class BucketACL:
    # assume both enabled by default so that the audit report never brings false negatives back
    all_users_enabled: bool = True
    authenticated_users_enabled: bool = True


def to_bucket_acl(acl: Dict[Any, Any]) -> BucketACL:
    grantees = [grant["Grantee"] for grant in acl["Grants"]]
    return BucketACL(
        all_users_enabled=any(map(lambda grantee: "AllUsers" in grantee.get("URI", ""), grantees)),
        authenticated_users_enabled=any(map(lambda grantee: "AuthenticatedUsers" in grantee.get("URI", ""), grantees)),
    )


@dataclass
class BucketContentDeny:
    enabled: bool = False


def to_bucket_content_deny(bucket_policy_dict: Dict[Any, Any]) -> BucketContentDeny:
    statements = loads(str(bucket_policy_dict.get("Policy"))).get("Statement")
    deny_actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    return BucketContentDeny(enabled=all(map(lambda action: _has_denied_action(statements, action), deny_actions)))


def _has_denied_action(statements: List[Dict[Any, Any]], action: str) -> bool:
    return any(map(lambda statement: _is_denied(statement, action), statements))


def _is_denied(statement: Dict[Any, Any], deny_action: str) -> bool:
    action = statement.get("Action")
    return statement.get("Effect") == "Deny" and (_is_action(action, deny_action) or _has_action(action, deny_action))


def _is_action(action: Any, expected: str) -> bool:
    return type(action) is str and action.startswith(expected)


def _has_action(actions: Any, expected: str) -> bool:
    return type(actions) is list and bool(list(filter(lambda action: _is_action(action, expected), actions)))


@dataclass
class BucketCORS:
    enabled: bool = True  # assume CORS is enabled by default so that the audit report never brings false negatives back


def to_bucket_cors(cors_config: Dict[Any, Any]) -> BucketCORS:
    return BucketCORS(enabled="CORSRules" in cors_config)


@dataclass
class BucketDataTagging:
    expiry: str = "unset"
    sensitivity: str = "unset"


def to_bucket_data_tagging(tag_response: Dict[str, List[Dict[str, str]]]) -> BucketDataTagging:
    tags = {tag["Key"]: tag["Value"] for tag in tag_response["TagSet"]}
    expiry = tags.get("data_expiry")
    sensitivity = tags.get("data_sensitivity")
    return BucketDataTagging(
        expiry=expiry
        if expiry
        in ["1-week", "1-month", "90-days", "6-months", "1-year", "7-years", "10-years", "forever-config-only"]
        else "unset",
        sensitivity=sensitivity if sensitivity in ["low", "high"] else "unset",
    )


@dataclass
class BucketEncryption:
    enabled: bool = False
    key: str = ""
    type: Optional[str] = None


def to_bucket_encryption(encryption_dict: Dict[Any, Any]) -> BucketEncryption:
    sse_config = encryption_dict["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
    algorithm = sse_config.get("SSEAlgorithm")
    key = sse_config.get("KMSMasterKeyID")

    return BucketEncryption(
        enabled=True,
        type="aes" if algorithm == "AES256" else "aws" if not key or "alias/aws/" in key else "cmk",
        key=key,
    )


@dataclass
class BucketLifecycle:
    current_version_expiry: Union[int, str] = "unset"
    previous_version_deletion: Union[int, str] = "unset"


def to_bucket_lifecycle(lifecycle_config: Dict[Any, Any]) -> BucketLifecycle:
    enabled_rules = list(filter(lambda rule: rule.get("Status") == "Enabled", lifecycle_config["Rules"]))
    current_version_rules = filter(lambda rule: "Expiration" in rule and "Days" in rule["Expiration"], enabled_rules)
    previous_version_rules = filter(
        lambda rule: "NoncurrentVersionExpiration" in rule and "NoncurrentDays" in rule["NoncurrentVersionExpiration"],
        enabled_rules,
    )
    return BucketLifecycle(
        current_version_expiry=min(
            map(lambda rule: int(rule["Expiration"]["Days"]), current_version_rules), default="unset"
        ),
        previous_version_deletion=min(
            map(lambda rule: int(rule["NoncurrentVersionExpiration"]["NoncurrentDays"]), previous_version_rules),
            default="unset",
        ),
    )


@dataclass
class BucketLogging:
    enabled: bool = False


def to_bucket_logging(logging_dict: Dict[Any, Any]) -> BucketLogging:
    return BucketLogging(enabled="LoggingEnabled" in logging_dict)


@dataclass
class BucketMFADelete:
    enabled: bool = False


def to_bucket_mfa_delete(versioning_dict: Dict[Any, Any]) -> BucketMFADelete:
    return BucketMFADelete(enabled=versioning_dict.get("MFADelete") == "Enabled")


@dataclass
class BucketPublicAccessBlock:
    enabled: bool = False


def to_bucket_public_access_block(public_access_block_dict: Dict[str, Dict[str, bool]]) -> BucketPublicAccessBlock:
    config = public_access_block_dict["PublicAccessBlockConfiguration"]
    return BucketPublicAccessBlock(enabled=config["IgnorePublicAcls"] and config["RestrictPublicBuckets"])


@dataclass
class BucketSecureTransport:
    enabled: bool = False


def to_bucket_secure_transport(bucket_policy_dict: Dict[Any, Any]) -> BucketSecureTransport:
    statements = loads(str(bucket_policy_dict.get("Policy"))).get("Statement")
    return BucketSecureTransport(enabled=bool(list(filter(_has_secure_transport, statements))))


def _has_secure_transport(policy: Dict[Any, Any]) -> bool:
    return policy.get("Effect") == "Deny" and policy.get("Condition") == {"Bool": {"aws:SecureTransport": "false"}}


@dataclass
class BucketVersioning:
    enabled: bool = False


def to_bucket_versioning(versioning_dict: Dict[Any, Any]) -> BucketVersioning:
    return BucketVersioning(enabled=versioning_dict.get("Status") == "Enabled")
