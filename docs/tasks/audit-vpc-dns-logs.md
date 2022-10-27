# Audit/Enforce VPC DNS log collection

The `audit_vpc_dns_logs` task can audit (or optionally create and update) AWS route53 and Cloudwatch resources needed to send logs of DNS queries to a central destination.

## Usage

```sh
./platsec_aws_scanner.sh create_flow_logs_table -u john.doo -t 123456 -y 2022 -m 2 -d 14

./platsec_aws_scanner.sh
 audit_vpc_dns_logs  --with_subscription_filter True -enforce False --skip_tag
s False
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.