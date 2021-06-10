# Service usage

The `service_usage` task scans CloudTrail logs for a given AWS service, account and data partition then reports on each
event name that occurred for this particular service and how many times each event fired.

## Usage

```sh
./platsec_aws_scanner.sh service_usage -u john.doo -t 123456 -y 2021 -m 3 -re ap-east-1 -a 999888777666 --service s3
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

- `-s / --service`: name of the AWS service that the task will scan usage for

## Task report

```json
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "some account"
    },
    "description": "AWS s3 service usage scan",
    "partition": {
      "year": "2021",
      "month": "03",
      "region": "ap-east-1"
    },
    "results": {
      "event_source": "s3.amazonaws.com",
      "service_usage": [
        {
          "event_name": "ListObjectVersions",
          "count": 15
        },
        {
          "event_name": "ListObjects",
          "count": 224
        },
        {
          "event_name": "GetBucketEncryption",
          "count": 11
        },
        {
          "event_name": "CreateMultipartUpload",
          "count": 6
        },
        {
          "event_name": "GetObject",
          "count": 205
        },
        {
          "event_name": "GetBucketLifecycle",
          "count": 1
        },
        {
          "event_name": "ListBuckets",
          "count": 125
        },
        {
          "event_name": "GetBucketPolicy",
          "count": 19
        },
        {
          "event_name": "GetBucketVersioning",
          "count": 52
        },
        {
          "event_name": "PutObject",
          "count": 31
        }
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `service_usage`: events list for this particular service in the requested account for the specified data partition

    - `event_name`: name of an event that occurred
    - `count`: how many times said event fired
