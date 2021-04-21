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
