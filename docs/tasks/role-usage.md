# Role usage

The `role_usage` task scans CloudTrail logs for a given AWS IAM role, account and data partition then reports on each
event name that occurred for this particular role and how many times each event fired.

## Usage

```sh
./platsec_aws_scanner.sh role_usage -u john.doo -t 123456 -y 2021 -m 3 -re eu-central-1 -a 999888777666 --role SomeIAMRole
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

- `-r / --role`: name of the AWS IAM role that the task will scan usage for

## Task report

```json
[
  {
    "account": {
      "identifier": "999888777666",
      "name": "some account"
    },
    "description": "AWS SomeIAMRole usage scan",
    "partition": {
      "year": "2021",
      "month": "03",
      "region": "eu-central-1"
    },
    "results": {
      "role_usage": [
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeChangeSet",
          "count": 44
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeStackEvents",
          "count": 53
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "DescribeStacks",
          "count": 73
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "ExecuteChangeSet",
          "count": 9
        },
        {
          "event_source": "cloudformation.amazonaws.com",
          "event_name": "ListStacks",
          "count": 69
        },
        {
          "event_source": "signin.amazonaws.com",
          "event_name": "RenewRole",
          "count": 2
        }
      ]
    }
  }
]
```

See the [task report section](../usage.md#task-report) for details on the common task report fields.

- `results`:

  - `role_usage`: events list for this particular IAM role in the requested account for the specified data partition

    - `event_source`: name of an AWS service for which an event occurred using this IAM role
    - `event_name`: name of an event that occurred
    - `count`: how many times said event fired
