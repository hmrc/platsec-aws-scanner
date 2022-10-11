from dataclasses import dataclass
from typing import Any, Dict

from src.clients.composite.aws_s3_kms_client import AwsS3KmsClient
from src.data.aws_organizations_types import Account
from src.data.aws_s3_types import Bucket, BucketCompliancy, ComplianceCheck
from src.tasks.aws_s3_task import AwsS3Task


@dataclass
class AwsAuditS3Task(AwsS3Task):
    def __init__(self, account: Account) -> None:
        super().__init__("audit S3 bucket compliance", account)

    def _run_task(self, client: AwsS3KmsClient) -> Dict[Any, Any]:
        return {
            "buckets": list(
                map(lambda bucket: self._set_compliance(client.enrich_bucket(bucket)), client.list_buckets())
            )
        }

    def _is_acl_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=(not bucket.acl.all_users_enabled and not bucket.acl.authenticated_users_enabled)
            if bucket.acl
            else False,
            message="bucket should not have ACL set",
        )

    def _is_content_deny_compliant(self, bucket: Bucket) -> ComplianceCheck:
        compliant = bucket.content_deny.enabled if bucket.content_deny else False
        if bucket.data_tagging:
            if bucket.data_tagging.sensitivity == "low":
                compliant = True
        return ComplianceCheck(
            compliant=compliant,
            message="bucket should have a resource policy with a default deny action",
        )

    def _is_encryption_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.encryption.enabled if bucket.encryption else False, message="bucket should be encrypted"
        )

    def _is_logging_compliant(self, bucket: Bucket) -> ComplianceCheck:
        # compliant = False
        if bucket.access_logging_tagging == "true":
            compliant = False
            skipped = True
        else:
            compliant = bucket.logging.enabled if bucket.logging else False
            skipped = False
        return ComplianceCheck(
            compliant=compliant,
            skipped=skipped,
            message="bucket should have logging enabled",
        )


    def _is_public_access_block_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.public_access_block.enabled if bucket.public_access_block else False,
            message="bucket should not allow public access",
        )

    def _is_secure_transport_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.secure_transport.enabled if bucket.secure_transport else False,
            message="bucket should have a resource policy with secure transport enforced",
        )

    def _is_versioning_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.versioning.enabled if bucket.versioning else False,
            message="bucket should have versioning enabled",
        )

    def _is_mfa_delete_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=(not bucket.mfa_delete.enabled if bucket.mfa_delete else False),
            message="MFA delete should be disabled",
        )

    def _is_kms_key_compliant(self, bucket: Bucket) -> ComplianceCheck:
        compliant = True if bucket.encryption and bucket.encryption.type == "aes" else False
        if bucket.kms_key:
            compliant = bucket.kms_key.rotation_enabled
        return ComplianceCheck(compliant, message="bucket kms key should have rotation enabled")

    def _is_tagging_compliant(self, bucket: Bucket) -> ComplianceCheck:
        compliant = False
        if bucket.data_tagging:
            compliant = bucket.data_tagging.expiry != "unset" and bucket.data_tagging.sensitivity != "unset"
        return ComplianceCheck(
            compliant=compliant,
            message="bucket should have tags for expiry and sensitivity",
        )

    def _is_lifecycle_compliant(self, bucket: Bucket) -> ComplianceCheck:
        compliant = False
        if bucket.lifecycle:
            compliant = (
                bucket.lifecycle.current_version_expiry != "unset"
                and bucket.lifecycle.previous_version_deletion != "unset"
            )
        if bucket.data_tagging:
            if bucket.data_tagging.expiry == "forever-config-only":
                compliant = True
        return ComplianceCheck(
            compliant=compliant,
            message="bucket should have a lifecycle configuration set for current/previous version",
        )

    def _is_cors_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=not bucket.cors.enabled if bucket.cors else False,
            message="bucket should not have CORS set",
        )

    def _set_compliance(self, bucket: Bucket) -> Bucket:
        bucket.compliancy = BucketCompliancy(
            content_deny=self._is_content_deny_compliant(bucket),
            acl=self._is_acl_compliant(bucket),
            encryption=self._is_encryption_compliant(bucket),
            logging=self._is_logging_compliant(bucket),
            public_access_block=self._is_public_access_block_compliant(bucket),
            secure_transport=self._is_secure_transport_compliant(bucket),
            versioning=self._is_versioning_compliant(bucket),
            mfa_delete=self._is_mfa_delete_compliant(bucket),
            kms_key=self._is_kms_key_compliant(bucket),
            tagging=self._is_tagging_compliant(bucket),
            lifecycle=self._is_lifecycle_compliant(bucket),
            cors=self._is_cors_compliant(bucket),
        )

        return bucket
