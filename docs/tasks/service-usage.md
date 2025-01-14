# Service usage

The `service_usage` task scans CloudTrail logs for AWS service(s), account and data partition then reports on each
event name that occurred for this particular service and how many times each event fired.

## Usage

```sh
./platsec_aws_scanner.sh service_usage -u john.doo -t 123456 -y 2021 -m 3 -re ap-east-1 -a 999888777666 --services s3
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

* `-s / --services`: comma-separated list of service(s) to scan usage for

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
          "error_code": "",
          "count": 15
        },
        {
          "event_name": "ListObjects",
          "error_code": "AccessDenied",
          "count": 224
        },
        {
          "event_name": "GetBucketEncryption",
          "error_code": "AccessDenied",
          "count": 11
        },
        {
          "event_name": "CreateMultipartUpload",
          "error_code": "",
          "count": 6
        },
        {
          "event_name": "GetObject",
          "error_code": "",
          "count": 205
        },
        {
          "event_name": "GetBucketLifecycle",
          "error_code": "",
          "count": 1
        },
        {
          "event_name": "ListBuckets",
          "error_code": "AccessDenied",
          "count": 125
        },
        {
          "event_name": "GetBucketPolicy",
          "error_code": "",
          "count": 19
        },
        {
          "event_name": "GetBucketVersioning",
          "error_code": "",
          "count": 52
        },
        {
          "event_name": "PutObject",
          "error_code": "",
          "count": 31
        }
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

* `results`:

  * `service_usage`: events list for this particular service in the requested account for the specified data partition

    * `event_name`: name of an event that occurred
    * `error_code`: if the event errors, an error code will populate otherwise the field will be empty
    * `count`: how many times said event fired
