# Audit Central Logging

The `audit_cloudtrail` task produces an audit report for [AWS Cloudtrail][aws-cloudtrail] of
a given account / list of accounts.

## Usage

```sh
./platsec_aws_scanner.sh audit_cloudtrail -t 123456 -a 999888777666
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

```json
[
  {
    "account": {
      "identifier": "186795123456",
      "name": "webops-staging"
    },
    "description": "audit Cloudtrail trails",
    "results": {
      "trails": [
        {
          "name": "Cloudtrail-Cloudtrail-QWERTYUIOP",
          "s3_bucket_name": "cloudtrail-all-accounts-22aa22b97b64286edf75be11aa11aa11",
          "is_logging": true,
          "is_multiregion_trail": true,
          "kms_key_id": "arn:aws:kms:eu-west-2:118949000000:key/1234abcd-6bd7-4e63-87ab-123abc456def",
          "log_file_validation_enabled": true,
          "include_global_service_events": true,
          "event_selectors": [
            {
              "read_write_type": "All",
              "include_management_events": true,
              "data_resources": [
                {
                  "type": "AWS::S3::Object",
                  "values": [
                    "arn:aws:s3"
                  ]
                }
              ]
            },
            {
              "read_write_type": "All",
              "include_management_events": true,
              "data_resources": [
                {
                  "type": "AWS::Lambda::Function",
                  "values": [
                    "arn:aws:lambda"
                  ]
                }
              ]
            },
            {
              "read_write_type": "All",
              "include_management_events": true,
              "data_resources": [
                {
                  "type": "AWS::DynamoDB::Table",
                  "values": [
                    "arn:aws:dynamodb"
                  ]
                }
              ]
            }
          ]
        }
      ],
      "log_group": {
        "name": "CloudTrail/DefaultLogGroup",
        "retention_days": 14
      }
    }
  },
  {
    "account": {
      "identifier": "415042754718",
      "name": "UpScan-live"
    },
    "description": "audit Cloudtrail trails",
    "results": {
      "trails": [
        {
          "name": "Cloudtrail-Cloudtrail-CYQ1NOQWERTY",
          "s3_bucket_name": "cloudtrail-all-accounts-22aa22b97b64286edf75be11aa11aa11",
          "is_logging": true,
          "is_multiregion_trail": true,
          "kms_key_id": "arn:aws:kms:eu-west-2:118949000000:key/1234abcd-6bd7-4e63-87ab-123abc456def",
          "log_file_validation_enabled": true,
          "include_global_service_events": true,
          "event_selectors": [
            {
              "read_write_type": "All",
              "include_management_events": true,
              "data_resources": [
                {
                  "type": "AWS::S3::Object",
                  "values": [
                    "arn:aws:s3"
                  ]
                }
              ]
            },
            {
              "read_write_type": "All",
              "include_management_events": true,
              "data_resources": [
                {
                  "type": "AWS::Lambda::Function",
                  "values": [
                    "arn:aws:lambda"
                  ]
                }
              ]
            },
            {
              "read_write_type": "All",
              "include_management_events": true,
              "data_resources": [
                {
                  "type": "AWS::DynamoDB::Table",
                  "values": [
                    "arn:aws:dynamodb"
                  ]
                }
              ]
            }
          ]
        }
      ],
      "log_group": {
        "name": "CloudTrail/DefaultLogGroup",
        "retention_days": 14
      }
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

* `results`:

  * `trails`: audit report of AWS Cloudtrail for given account(s).

[aws-cloudtrail]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
