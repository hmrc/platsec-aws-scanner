from __future__ import annotations
from dataclasses import dataclass
from functools import reduce
from json import loads
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Bucket:
    name: str
    content_deny: Optional[BucketContentDeny] = None
    data_sensitivity_tagging: Optional[BucketDataSensitivityTagging] = None
    encryption: Optional[BucketEncryption] = None
    logging: Optional[BucketLogging] = None
    mfa_delete: Optional[BucketMFADelete] = None
    public_access_block: Optional[BucketPublicAccessBlock] = None
    secure_transport: Optional[BucketSecureTransport] = None


def to_bucket(bucket_dict: Dict[Any, Any]) -> Bucket:
    return Bucket(name=bucket_dict["Name"])


@dataclass
class BucketContentDeny:
    enabled: bool = False


def to_bucket_content_deny(bucket_policy_dict: Dict[Any, Any]) -> BucketContentDeny:
    statements = loads(str(bucket_policy_dict.get("Policy"))).get("Statement")
    deny_actions = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    return BucketContentDeny(
        enabled=reduce(lambda a, b: a and b, map(lambda action: _has_denied_action(statements, action), deny_actions))
    )


def _has_denied_action(statements: List[Dict[Any, Any]], action: str) -> bool:
    return reduce(lambda a, b: a or b, map(lambda statement: _is_denied(statement, action), statements))


def _is_denied(statement: Dict[Any, Any], deny_action: str) -> bool:
    action = statement.get("Action")
    return statement.get("Effect") == "Deny" and (_is_action(action, deny_action) or _has_action(action, deny_action))


def _is_action(action: Any, expected: str) -> bool:
    return type(action) is str and action.startswith(expected)


def _has_action(actions: Any, expected: str) -> bool:
    return type(actions) is list and bool(list(filter(lambda action: _is_action(action, expected), actions)))


@dataclass
class BucketEncryption:
    enabled: bool = False
    type: Optional[str] = None


def to_bucket_encryption(encryption_dict: Dict[Any, Any]) -> BucketEncryption:
    sse_config = encryption_dict["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
    algorithm = sse_config.get("SSEAlgorithm")
    key = sse_config.get("KMSMasterKeyID")

    algo_mapping: Dict[str, Callable[[], BucketEncryption]] = {
        "AES256": lambda: BucketEncryption(enabled=True, type="aes"),
        "aws:kms": lambda: BucketEncryption(enabled=True, type="aws" if not key or "alias/aws/" in key else "cmk"),
    }

    return algo_mapping[algorithm]()


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
class BucketSecureTransport:
    enabled: bool = False


def to_bucket_secure_transport(bucket_policy_dict: Dict[Any, Any]) -> BucketSecureTransport:
    statements = loads(str(bucket_policy_dict.get("Policy"))).get("Statement")
    return BucketSecureTransport(enabled=bool(list(filter(_has_secure_transport, statements))))


def _has_secure_transport(policy: Dict[Any, Any]) -> bool:
    return policy.get("Effect") == "Deny" and policy.get("Condition") == {"Bool": {"aws:SecureTransport": "false"}}


@dataclass
class BucketPublicAccessBlock:
    enabled: bool = False


def to_bucket_public_access_block(public_access_block_dict: Dict[str, Dict[str, bool]]) -> BucketPublicAccessBlock:
    config = public_access_block_dict["PublicAccessBlockConfiguration"]
    return BucketPublicAccessBlock(enabled=config["IgnorePublicAcls"] and config["RestrictPublicBuckets"])


@dataclass
class BucketDataSensitivityTagging:
    enabled: bool = False
    type: Optional[str] = None


def to_bucket_data_sensitivity_tagging(tag_dict: Dict[str, List[Dict[str, str]]]) -> BucketDataSensitivityTagging:
    tags = list(filter(lambda t: t["Key"] == "data_sensitivity" and t["Value"] in ["high", "low"], tag_dict["TagSet"]))
    data_sensitivity = tags[0]["Value"] if tags else None
    return BucketDataSensitivityTagging(enabled=bool(data_sensitivity), type=data_sensitivity)
