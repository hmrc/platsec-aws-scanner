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
          "data_sensitivity_tagging": {
            "enabled": false
          },
          "encryption": {
            "enabled": true,
            "type": "cmk"
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
          }
        },
        {
          "name": "another-bucket",
          "content_deny":  {
            "enabled":  false
          },
          "data_sensitivity_tagging":  {
            "enabled": true,
            "type": "high"
          },
          "encryption": {
            "enabled": false
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
