# platsec-aws-scanner

PlatSec AWS Scanner is a Python command-line tool that can run parallel tasks against a set of AWS accounts. Tasks can
be anything, from querying CloudTrail logs with Athena, scanning for AWS service and AWS IAM role usage, finding
principals by source IP address, listing accounts in an AWS organization, etc.

## Documentation

Explore the [documentation directory](docs) to learn more about the requirements, configuration and usage of PlatSec AWS
Scanner.

## Usage example

```sh
./platsec_aws_scanner.sh role_usage -u john.doo --token 123456 --year 2021 --month 3 --role SomeIAMRole
```

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
      "region": "eu-west-1"
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
          "event_name": "ExecuteChangeSet",
          "count": 9
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
