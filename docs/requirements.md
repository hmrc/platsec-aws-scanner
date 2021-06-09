# Requirements

## 1. AWS infrastructure

The scanning tasks will work out of the box for any AWS infrastructure where the following conditions are met:

-   an AWS account exists and consolidates the other AWS accounts through the
    [AWS Organizations service][aws-organizations]

-   an AWS account exists and collects [CloudTrail logs][aws-cloudtrail] from some/all the other AWS accounts

-   an AWS account exists with IAM users that have delegate access on the roles that are assumed by the scanning tasks

**Notes**

- identifiers and roles for these AWS accounts should be present in [the configuration file](configuration.md)
- these accounts can be distinct but do not have to, as long as all the above conditions are met

## 2. Machine setup

The machine that runs this tool needs Python with [this version or greater](../.python-version), a
[Python virtual environment][python-venv] where the [dependencies](../Pipfile) are fetched. [Pipenv][python-pipenv] can
be used to create this virtual environment.

Installing pipenv:

```sh
pip install --user pipenv
```

Creating the virtual environment, from the root of this project:

```sh
pipenv install --dev
```

Activating the virtual environment, from the root of this project:

```sh
pipenv shell
```

Then within the activated virtual environment, the scanner can be invoked as such:

```sh
./platsec_aws_scanner.py [command] [options]
```

[aws-cloudtrail]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html
[aws-organizations]: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_introduction.html
[python-venv]: https://docs.python.org/3/library/venv.html
[python-pipenv]: https://pipenv.pypa.io/en/latest/
