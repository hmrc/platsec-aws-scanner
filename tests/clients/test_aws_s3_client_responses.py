from json import dumps
from typing import Dict

LIST_BUCKETS = {
    "Buckets": [
        {"Name": "a-bucket", "CreationDate": "2015, 1, 1"},
        {"Name": "another-bucket", "CreationDate": "2015, 1, 1"},
    ],
    "Owner": {"DisplayName": "string", "ID": "string"},
}

GET_BUCKET_ENCRYPTION_CMK = {
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
GET_BUCKET_ENCRYPTION_AWS_MANAGED = {
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
GET_BUCKET_ENCRYPTION_AES = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256",
                }
            }
        ]
    }
}
GET_BUCKET_ENCRYPTION_KEYLESS = {
    "ServerSideEncryptionConfiguration": {
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
    }
}

GET_BUCKET_LOGGING_ENABLED = {
    "LoggingEnabled": {"TargetBucket": "some-target-bucket", "TargetPrefix": "some-target-prefix"}
}
GET_BUCKET_LOGGING_DISABLED = {}

GET_BUCKET_POLICY = {
    "Policy": '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:getObject", "Resource": "*"}]}'
}
GET_BUCKET_POLICY_SECURE_TRANSPORT = {
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


def public_access_block(
    block_public_acls: bool, ignore_public_acls: bool, block_public_policy: bool, restrict_public_buckets: bool
) -> Dict[str, Dict[str, bool]]:
    return {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets,
        }
    }


GET_BUCKET_TAGGING_HIGH_SENSITIVITY = {"TagSet": [{"Key": "data_sensitivity", "Value": "high"}]}
GET_BUCKET_TAGGING_LOW_SENSITIVITY = {"TagSet": [{"Key": "data_sensitivity", "Value": "low"}]}
GET_BUCKET_TAGGING_UNKNOWN_SENSITIVITY = {"TagSet": [{"Key": "data_sensitivity", "Value": "unexpected"}]}
GET_BUCKET_TAGGING_NO_SENSITIVITY = {"TagSet": [{"Key": "some_tag", "Value": "some_value"}]}

GET_BUCKET_TAGGING_EXPIRY_1_WEEK = {"TagSet": [{"Key": "data_expiry", "Value": "1-week"}]}
GET_BUCKET_TAGGING_EXPIRY_1_MONTH = {"TagSet": [{"Key": "data_expiry", "Value": "1-month"}]}
GET_BUCKET_TAGGING_EXPIRY_90_DAYS = {"TagSet": [{"Key": "data_expiry", "Value": "90-days"}]}
GET_BUCKET_TAGGING_EXPIRY_6_MONTHS = {"TagSet": [{"Key": "data_expiry", "Value": "6-months"}]}
GET_BUCKET_TAGGING_EXPIRY_1_YEAR = {"TagSet": [{"Key": "data_expiry", "Value": "1-year"}]}
GET_BUCKET_TAGGING_EXPIRY_7_YEARS = {"TagSet": [{"Key": "data_expiry", "Value": "7-years"}]}
GET_BUCKET_TAGGING_EXPIRY_10_YEARS = {"TagSet": [{"Key": "data_expiry", "Value": "10-years"}]}
GET_BUCKET_TAGGING_EXPIRY_UNKNOWN = {"TagSet": [{"Key": "data_expiry", "Value": "unexpected"}]}
GET_BUCKET_TAGGING_NO_EXPIRY = {"TagSet": [{"Key": "some_other_tag", "Value": "some_other_value"}]}

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
    "Rules": [{"Expiration": {"Days": 15}, "Status": "Enabled", "NoncurrentVersionExpiration": {"NoncurrentDays": 30}}]
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
