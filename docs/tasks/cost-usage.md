# Cost Usage

The `cost_explorer` task outputs data showing the usage & cost of a specified service in a given account / list of accounts
.

The service being queried needs to be specified using its full name, example:

- Amazon Api Gateway
- Amazon Cloudfront
- Amazon DynamoDB
- Amazon Simple Storage Service
- Amazon Virtual Private Cloud
- AWS CodePipeline
- AWS CodeBuild
- AWS CodeArtifact
- AWS Lambda
- AWS X-Ray

You can see a list of full names of services by clicking on the service [here](https://docs.aws.amazon.com/index.html),
then you'll see the full name on the next page, i.e "**Amazon Simple Storage Service** Documentation".

## Usage

```sh
./platsec_aws_scanner.sh cost_explorer -m 07 -y 2021 -s "AWS Lambda" -u john.doo -t 123456 -a 999888777666
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
