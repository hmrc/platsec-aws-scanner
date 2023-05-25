# Audit Central Logging

The `audit_central_logging` task produces an audit report logging into the account used for storing 
[AWS Cloudtrail][aws-cloudtrail] logs for all accounts in the organization.

## Usage

```sh
./platsec_aws_scanner.sh audit_central_logging -t 123456
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

```json
[
  {
    "account": {
      "identifier": "118949000000",
      "name": "cloudtrail"
    },
    "description": "audit central logging account",
    "results": {
      "events_bucket": {
        "name": "cloudtrail-all-accounts-111a7b97b64286edf75be9731111111",
        "policy": {
          "Version": "2008-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "s3:GetBucketAcl",
              "Resource": "arn:aws:s3:::cloudtrail-all-accounts-111a7b97b64286edf75be9731111111"
            },
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "s3:PutObject",
              "Resource": [
                "arn:aws:s3:::cloudtrail-all-accounts-111a7b97b64286edf75be9731111111/AWSLogs/813602111111/*",
                "arn:aws:s3:::cloudtrail-all-accounts-2229a7b97b64286edf75be9732222222/AWSLogs/813602222222/*",
              ],
              "Condition": {
                "StringEquals": {
                  "s3:x-amz-acl": "bucket-owner-full-control"
                }
              }
            },
            {
              "Sid": "DenyIncorrectEncryptionHeaderAndKey",
              "Effect": "Deny",
              "Principal": "*",
              "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::cloudtrail-all-accounts-1a1a1a1a1a64286edf75be973dbae072/*",
              "Condition": {
                "StringNotEqualsIfExists": {
                  "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:eu-west-2:118949000000:key/077d2d0b-6bd7-4e63-87ab-2788b418e8ae"
                },
                "StringNotEquals": {
                  "s3:x-amz-server-side-encryption": [
                    "aws:kms",
                    "AES256"
                  ]
                }
              }
            },
            {
              "Sid": "DenyUnEncryptedObjectUploads",
              "Effect": "Deny",
              "Principal": "*",
              "Action": "s3:PutObject",
              "Resource": "arn:aws:s3:::cloudtrail-all-accounts-1a1a1a1a1a64286edf75be973dbae072/*",
              "Condition": {
                "Null": {
                  "s3:x-amz-server-side-encryption": "true"
                }
              }
            }
          ]
        }
      },
      "events_cmk": {
        "account_id": "118949000000",
        "region": "eu-west-2",
        "id": "11111111-6bd7-4e63-87ab-2788b1111111",
        "arn": "arn:aws:kms:eu-west-2:118949000000:key/11111111-6bd7-4e63-87ab-2788b1111111",
        "description": "Key used by cloudtrail S3 bucket to encrypt cloudtrail logs",
        "state": "Enabled",
        "policy": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:DescribeKey"
              ],
              "Resource": "*"
            },
            {
              "Effect": "Allow",
              "Principal": {
                "Service": "cloudtrail.amazonaws.com"
              },
              "Action": "kms:GenerateDataKey*",
              "Resource": "*",
              "Condition": {
                "StringLike": {
                  "kms:EncryptionContext:aws:cloudtrail:arn": [
                    "arn:aws:cloudtrail:*:111111564517:trail/*",
                    "arn:aws:cloudtrail:*:111111564516:trail/*"
                  ]
                }
              }
            },
            {
              "Effect": "Allow",
              "Principal": {
                "AWS": "arn:aws:iam::118949000000:root"
              },
              "Action": "kms:*",
              "Resource": "*"
            }
          ]
        }
      },
      "org_accounts": [
        {
          "identifier": "111111564516",
          "name": "this account"
        },
        {
          "identifier": "111111564517",
          "name": "that account"
        }
      ]
    }
  }
]

```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `trails`: audit report logging into the central logging account.

[aws-cloudtrail]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
