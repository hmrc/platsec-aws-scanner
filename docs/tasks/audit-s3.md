# Audit S3

The `audit_s3` task produces an audit report for [AWS S3 buckets][aws-s3-bucket] of a given account / list of accounts.

> This task is under development.

## Usage

```sh
./platsec_aws_scanner.sh audit_s3 -u john.doo -t 123456 -a 999888777666
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Task report

```json
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "some account"
    },
    "description": "audit S3 bucket compliance",
    "results": {
      "buckets": [
        {
          "name": "a-bucket",
          "content_deny": {
            "enabled": true
          },
          "cors": {
            "enabled": false
          },
          "data_tagging": {
            "expiry": "1-week",
            "sensitivity": "high"
          },
          "encryption": {
            "enabled": true,
            "type": "cmk"
          },
          "lifecycle": {
            "current_version_expiry": 7,
            "previous_version_deletion": 14
          },
          "logging": {
            "enabled": false
          },
          "mfa_delete": {
            "enabled": true
          },
          "public_access_block": {
            "enabled": false
          },
          "secure_transport": {
            "enabled": false
          },
          "versioning": {
            "enabled": true
          }
        },
        {
          "name": "another-bucket",
          "content_deny":  {
            "enabled":  false
          },
          "cors": {
            "enabled": true
          },
          "data_tagging": {
            "expiry": "90-days",
            "sensitivity": "unset"
          },
          "encryption": {
            "enabled": false
          },
          "lifecycle": {
            "current_version_expiry": 366,
            "previous_version_deletion": "unset"
          },
          "logging": {
            "enabled": true
          },
          "mfa_delete":  {
            "enabled": false
          },
          "public_access_block": {
            "enabled": true
          },
          "secure_transport":  {
            "enabled": true
          },
          "versioning": {
            "enabled":  false
          }
        }
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `buckets`: audit report of AWS S3 buckets for given account

[aws-s3-bucket]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#BasicsBucket
