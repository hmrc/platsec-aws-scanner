# Audit/Enforce VPC DNS log collection

The `audit_vpc_dns_logs` task audits (or optionally create/updates)
sending logs DNS query logs to a central destination.

## Usage

```sh
./platsec_aws_scanner.sh audit_vpc_dns_logs  --with_subscription_filter True -enforce False --skip_tags False
```

See the [common arguments section](../usage.md#common-arguments) for details on the common arguments.
