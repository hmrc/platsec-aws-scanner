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
            compliant=(not bucket.acl.all_users_enabled and not bucket.acl.authenticated_users_enabled),
            message="bucket should not have ACL set"
        )

    def _is_content_deny_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.content_deny.enabled,
            message="bucket should have a resource policy with a default deny action"
        )

    def _is_encryption_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.encryption.enabled,
            message="bucket should be encrypted"
        )

    def _is_logging_compliant(self, bucket: Bucket) -> ComplianceCheck:
        return ComplianceCheck(
            compliant=bucket.logging.enabled,
            message="bucket should have logging enabled"
        )


    def _set_compliance(self, bucket: Bucket) -> Bucket:
        bucket.compliancy = BucketCompliancy(
            content_deny=self._is_content_deny_compliant(bucket),
            acl=self._is_acl_compliant(bucket),
            encryption=self._is_encryption_compliant(bucket),
            logging=self._is_logging_compliant(bucket),
        )
        # we want these enabled
      
        """  if bucket.encryption:
            bucket.encryption.compliant = bucket.encryption.enabled """

        """ if bucket.logging:
            bucket.logging.compliant = bucket.logging.enabled

        if bucket.public_access_block:
            bucket.public_access_block.compliant = bucket.public_access_block.enabled

        if bucket.secure_transport:
            bucket.secure_transport.compliant = bucket.secure_transport.enabled """

        """  if bucket.versioning:
            bucket.versioning.compliant = bucket.versioning.enabled """

        # these just default to being compliant, status disregarded in policy
        """ if bucket.mfa_delete:
            bucket.mfa_delete.compliant = True """

        """ if bucket.kms_key:
            bucket.kms_key.compliant = bucket.kms_key.rotation_enabled """

        """ if bucket.data_tagging:
            bucket.data_tagging.compliant = (
                bucket.data_tagging.expiry != "unset" and bucket.data_tagging.sensitivity != "unset"
            ) """

        """ if bucket.lifecycle:
            bucket.lifecycle.compliant = (
                bucket.lifecycle.current_version_expiry != "unset"
                and bucket.lifecycle.previous_version_deletion != "unset"
            )
 """

        """ if bucket.cors:
            bucket.cors.compliant = not bucket.cors.enabled """

        return bucket
