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
