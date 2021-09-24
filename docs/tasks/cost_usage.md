# Cost Usage

The `cost_usage` task outputs data showing the usage & cost of a specified service in a given account / list of accounts.

The service being queried needs to be specified using its full name, example:
 - AWS Lambda
 - Amazon Api Gateway
 - Amazon Cloudfront
 - Amazon Simple Storage Service
 - Amazon Virtual Private Cloud
 - AWS CodePipeline
 - AWS CodeBuild
 - AWS CodeArtifact
 - AWS X-Ray
 - Amazon DynamoDB

## Usage

```sh
./platsec_aws_scanner.sh cost_usage -m 07 -y 2021 -s "AWS Lambda" -u john.doo -t 123456 -a 999888777666
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.

## Response

```json
[{
	"account": {
		"identifier": "324599906584",
		"name": "platsec-production"
	},
	"description": "cost & usage of AWS Lambda",
	"results": {
		"Service": "AWS Lambda",
		"DateRange": {
			"Start": "2021-07-01",
			"End": "2021-09-24"
		},
		"TotalCost:": "USD 513",
		"TotalUsage": "41485454"
	}
}]
```
