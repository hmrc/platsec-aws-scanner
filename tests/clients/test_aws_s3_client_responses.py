from json import dumps
from io import BytesIO
from typing import Dict, Any

from botocore.response import StreamingBody

LIST_BUCKETS: Dict[str, Any] = {
    "Buckets": [
        {"Name": "a-bucket", "CreationDate": "2015, 1, 1"},
        {"Name": "another-bucket", "CreationDate": "2015, 1, 1"},
        {"Name": "other-region-bucket", "CreationDate": "2010, 1, 1"},
    ],
    "Owner": {"DisplayName": "string", "ID": "string"},
}

# Buckets in Region us-east-1 have a LocationConstraint of null
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#S3.Client.get_bucket_location
GET_BUCKET_LOCATION_US_EAST_1 = {"LocationConstraint": None}

GET_BUCKET_LOCATION_CURRENT = {"LocationConstraint": "our-current-region"}

GET_BUCKET_LOCATION_OTHER = {"LocationConstraint": "other-region"}

GET_BUCKET_ENCRYPTION_CMK: Dict[str, Any] = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "65465465-ab56-423f-ec22-c45623212123",
                }
            }
        ]
    }
}
GET_BUCKET_ENCRYPTION_AWS_MANAGED: Dict[str, Any] = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "aws:kms",
                    "KMSMasterKeyID": "arn:aws:kms:some-region:455687898753:alias/aws/s3",
                }
            }
        ]
    }
}
GET_BUCKET_ENCRYPTION_AES: Dict[str, Any] = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                    "KMSMasterKeyID": "",
                }
            }
        ]
    }
}
GET_BUCKET_ENCRYPTION_KEYLESS: Dict[str, Any] = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
    }
}

GET_BUCKET_LOGGING_ENABLED: Dict[str, Any] = {
    "LoggingEnabled": {"TargetBucket": "some-target-bucket", "TargetPrefix": "some-target-prefix"}
}
GET_BUCKET_LOGGING_DISABLED: Dict[str, Any] = {}

GET_BUCKET_POLICY: Dict[str, Any] = {
    "Policy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:getObject", "Resource": "*"}]}'
}
GET_BUCKET_POLICY_SECURE_TRANSPORT: Dict[str, Any] = {
    "Policy": """{
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::some-bucket/*",
                "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}
            },
            {
                "Sid": "2",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::secure-bucket/*",
                    "arn:aws:s3:::secure-bucket"
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            }
        ]
    }"""
}
GET_BUCKET_POLICY_SECURE_TRANSPORT_BAD_ACTION: Dict[str, Any] = {
    "Policy": """{
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::almost-secure-bucket/*",
                "Condition": {"Null": {"s3:x-amz-server-side-encryption": "true"}}
            },
            {
                "Sid": "2",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": [
                    "arn:aws:s3:::almost-secure-bucket/*",
                    "arn:aws:s3:::almost-secure-bucket"
                ],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            }
        ]
    }"""
}


def public_access_block(
    block_public_acls: bool, ignore_public_acls: bool, block_public_policy: bool, restrict_public_buckets: bool
) -> Dict[str, Any]:
    return {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets,
        }
    }


GET_BUCKET_TAGGING_HIGH_SENSITIVITY = {
    "TagSet": [{"Key": "data_sensitivity", "Value": "high"}, {"Key": "data_expiry", "Value": "1-week"}]
}
GET_BUCKET_TAGGING_LOW_SENSITIVITY = {
    "TagSet": [{"Key": "data_sensitivity", "Value": "low"}, {"Key": "data_expiry", "Value": "1-week"}]
}
GET_BUCKET_TAGGING_UNKNOWN_SENSITIVITY = {"TagSet": [{"Key": "data_sensitivity", "Value": "unexpected"}]}
GET_BUCKET_TAGGING_NO_SENSITIVITY = {"TagSet": [{"Key": "some_tag", "Value": "some_value"}]}

GET_BUCKET_TAGGING_EXPIRY_1_WEEK = {
    "TagSet": [{"Key": "data_expiry", "Value": "1-week"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_1_MONTH = {
    "TagSet": [{"Key": "data_expiry", "Value": "1-month"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_90_DAYS = {
    "TagSet": [{"Key": "data_expiry", "Value": "90-days"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_6_MONTHS = {
    "TagSet": [{"Key": "data_expiry", "Value": "6-months"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_18_MONTHS = {
    "TagSet": [{"Key": "data_expiry", "Value": "18-months"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_1_YEAR = {
    "TagSet": [{"Key": "data_expiry", "Value": "1-year"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_7_YEARS = {
    "TagSet": [{"Key": "data_expiry", "Value": "7-years"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_10_YEARS = {
    "TagSet": [{"Key": "data_expiry", "Value": "10-years"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_FOREVER_CONFIG_ONLY = {
    "TagSet": [{"Key": "data_expiry", "Value": "forever-config-only"}, {"Key": "data_sensitivity", "Value": "low"}]
}
GET_BUCKET_TAGGING_EXPIRY_UNKNOWN = {"TagSet": [{"Key": "data_expiry", "Value": "unexpected"}]}
GET_BUCKET_TAGGING_NO_EXPIRY = {"TagSet": [{"Key": "some_other_tag", "Value": "some_other_value"}]}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_TRUE_LOWER = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "true"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_TRUE_CAMEL = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "True"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_TRUE_UPPER = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "true"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_FALSE_LOWER = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "false"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_FALSE_CAMEL = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "false"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_FALSE_UPPER = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "false"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_LOGGING_UNKNOWN = {
    "TagSet": [{"Key": "ignore_access_logging_check", "Value": "unexpected"}]
}
GET_BUCKET_TAGGING_IGNORE_ACCESS_NO_LOGGING = {"TagSet": [{"Key": "some_tag", "Value": "some_value"}]}

GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_SINGLE_STATEMENT = {
    "Policy": dumps({"Statement": [{"Effect": "Deny", "Action": ["s3:GetObject*", "s3:PutObject", "s3:DeleteObject"]}]})
}
GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_SEPARATE_STATEMENTS = {
    "Policy": dumps(
        {
            "Statement": [
                {"Effect": "Deny", "Action": "s3:GetObject"},
                {"Effect": "Deny", "Action": "s3:PutObject*"},
                {"Effect": "Deny", "Action": "s3:DeleteObject"},
            ]
        }
    )
}
GET_BUCKET_POLICY_DENY_GET_PUT_DELETE_MIXED_STATEMENTS = {
    "Policy": dumps(
        {
            "Statement": [
                {"Effect": "Deny", "Action": ["s3:GetObject", "s3:PutObject"]},
                {"Effect": "Deny", "Action": "s3:DeleteObject*"},
            ]
        }
    )
}
GET_BUCKET_POLICY_DENY_GET_PUT_SINGLE_STATEMENT = {
    "Policy": dumps({"Statement": [{"Effect": "Deny", "Action": ["s3:GetObject", "s3:PutObject"]}]})
}
GET_BUCKET_POLICY_DENY_GET_DELETE_SEPARATE_STATEMENTS = {
    "Policy": dumps(
        {"Statement": [{"Effect": "Deny", "Action": "s3:GetObject"}, {"Effect": "Deny", "Action": "s3:DeleteObject"}]}
    )
}
GET_BUCKET_POLICY_DENY_PUT_DELETE_MIXED_STATEMENTS = {
    "Policy": dumps(
        {
            "Statement": [
                {"Effect": "Deny", "Action": ["s3:SomethingElse", "s3:PutObject"]},
                {"Effect": "Deny", "Action": "s3:DeleteObject"},
            ]
        }
    )
}
GET_BUCKET_POLICY_ALLOW_GET_PUT_DELETE_MIXED_STATEMENTS = {
    "Policy": dumps(
        {
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"]},
                {"Effect": "Allow", "Action": "s3:DeleteObject"},
            ]
        }
    )
}
GET_BUCKET_POLICY_DENY_OTHER = {"Policy": dumps({"Statement": [{"Effect": "Deny", "Action": "s3:SomeAction"}]})}

GET_BUCKET_VERSIONING_MFA_DELETE_ENABLED = {"Status": "whatever", "MFADelete": "Enabled"}
GET_BUCKET_VERSIONING_MFA_DELETE_DISABLED = {"Status": "whatever", "MFADelete": "Disabled"}
GET_BUCKET_VERSIONING_MFA_DELETE_UNSET = {"Status": "whatever"}

GET_BUCKET_VERSIONING_ENABLED = {"Status": "Enabled", "MFADelete": "whatever"}
GET_BUCKET_VERSIONING_SUSPENDED = {"Status": "Suspended", "MFADelete": "whatever"}
GET_BUCKET_VERSIONING_UNSET = {"MFADelete": "whatever"}

GET_BUCKET_LIFECYCLE_CONFIGURATION_SINGLE_RULE = {
    "Rules": [
        {"Expiration": {"Date": 0}, "Status": "Enabled", "NoncurrentVersionExpiration": {"NewerNoncurrentVersions": 1}}
    ]
}
GET_BUCKET_LIFECYCLE_CONFIGURATION_MULTIPLE_RULES = {
    "Rules": [
        {"Expiration": {"Days": 15}, "Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 10}},
        {"Expiration": {"Days": 5}, "Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}},
    ]
}
GET_BUCKET_LIFECYCLE_CONFIGURATION_DISABLED = {
    "Rules": [{"Expiration": {"Days": 15}, "Status": "Disabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]
}
GET_BUCKET_LIFECYCLE_CONFIGURATION_NO_EXPIRY = {
    "Rules": [{"Status": "Enabled", "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 45}}]
}

GET_BUCKET_CORS_ENABLED = {"CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["*"]}]}

GET_BUCKET_ACL_NO_GRANT = {"Owner": {"ID": "some_id"}, "Grants": []}
GET_BUCKET_ACL_OWNER_GRANT = {"Owner": {"ID": "some_id"}, "Grants": [{"Grantee": {"ID": "some_id"}}]}
GET_BUCKET_ACL_ALL_USERS_GRANT = {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}
GET_BUCKET_ACL_AUTHENTICATED_USERS_GRANT = {
    "Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"}}]
}

PUT_OBJECT = {"VersionId": "some id"}

GET_OBJECT = {"Body": StreamingBody(BytesIO("banana".encode("utf-8")), len("banana".encode("utf-8")))}
