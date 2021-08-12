import boto3

from dataclasses import dataclass
from logging import getLogger
from typing import Any, Callable, Optional

from botocore.client import BaseClient
from botocore.exceptions import ClientError, BotoCoreError

from src.aws_scanner_config import AwsScannerConfig as Config
from src.clients.aws_athena_client import AwsAthenaClient
from src.clients.aws_ec2_client import AwsEC2Client
from src.clients.aws_logs_client import AwsLogsClient
from src.clients.aws_organizations_client import AwsOrganizationsClient
from src.clients.aws_ssm_client import AwsSSMClient
from src.clients.aws_s3_client import AwsS3Client
from src.data import SERVICE_ACCOUNT_USER
from src.data.aws_organizations_types import Account
from src.data.aws_scanner_exceptions import ClientFactoryException


@dataclass
class AwsCredentials:
    accessKeyId: str
    secretAccessKey: str
    sessionToken: str


class AwsClientFactory:
    def __init__(self, mfa: str, username: str):
        self._logger = getLogger(self.__class__.__name__)
        self._config = Config()
        self._session_token = self._get_session_token(mfa, username)

    def get_athena_boto_client(self) -> BaseClient:
        return self._get_client("athena", self._config.athena_account(), self._config.athena_role())

    def get_s3_boto_client(self, account: Account, role: str) -> BaseClient:
        return self._get_client("s3", account, role)

    def get_s3_client(self, account: Account, role: Optional[str] = None) -> AwsS3Client:
        return AwsS3Client(self.get_s3_boto_client(account, role or self._config.s3_role()))

    def get_organizations_boto_client(self) -> BaseClient:
        return self._get_client("organizations", self._config.organization_account(), self._config.organization_role())

    def get_ssm_boto_client(self, account: Account) -> BaseClient:
        return self._get_client("ssm", account, self._config.ssm_role())

    def get_logs_boto_client(self, account: Account) -> BaseClient:
        return self._get_client("logs", account, self._config.logs_role())

    def get_athena_client(self) -> AwsAthenaClient:
        return AwsAthenaClient(self.get_athena_boto_client())

    def get_ec2_boto_client(self, account: Account) -> BaseClient:
        return self._get_client("ec2", account, self._config.ec2_role())

    def get_ec2_client(self, account: Account) -> AwsEC2Client:
        return AwsEC2Client(self.get_ec2_boto_client(account))

    def get_organizations_client(self) -> AwsOrganizationsClient:
        return AwsOrganizationsClient(self.get_organizations_boto_client())

    def get_ssm_client(self, account: Account) -> AwsSSMClient:
        return AwsSSMClient(self.get_ssm_boto_client(account))

    def get_logs_client(self, account: Account) -> AwsLogsClient:
        return AwsLogsClient(self.get_logs_boto_client(account))

    def _get_session_token(self, mfa: str, username: str) -> Optional[AwsCredentials]:
        self._logger.info(f"getting session token for {username}")
        return (
            None
            if username == SERVICE_ACCOUNT_USER
            else self._to_credentials(
                lambda: boto3.client(service_name="sts").get_session_token(
                    DurationSeconds=self._config.session_duration_seconds(),
                    SerialNumber=f"arn:aws:iam::{self._config.user_account().identifier}:mfa/{username}",
                    TokenCode=mfa,
                )
            )
        )

    @staticmethod
    def _to_credentials(credentials_provider: Callable[[], Any]) -> AwsCredentials:
        try:
            credentials_dict = credentials_provider()
        except (ClientError, BotoCoreError) as err:
            raise ClientFactoryException(err) from None

        return AwsCredentials(
            accessKeyId=credentials_dict["Credentials"]["AccessKeyId"],
            secretAccessKey=credentials_dict["Credentials"]["SecretAccessKey"],
            sessionToken=credentials_dict["Credentials"]["SessionToken"],
        )

    def _get_client(self, service_name: str, account: Account, role: str) -> BaseClient:
        assumed_role = self._assume_role(account, role)
        self._logger.info(f"creating {service_name} client for {role} in {account}")
        return boto3.client(
            service_name=service_name,
            aws_access_key_id=assumed_role.accessKeyId,
            aws_secret_access_key=assumed_role.secretAccessKey,
            aws_session_token=assumed_role.sessionToken,
        )

    def _assume_role(self, account: Account, role: str) -> AwsCredentials:
        self._logger.info(f"assuming {role} in {account}")
        return self._to_credentials(
            lambda: self._sts().assume_role(
                DurationSeconds=self._config.session_duration_seconds(),
                RoleArn=f"arn:aws:iam::{account.identifier}:role/{role}",
                RoleSessionName=f"boto3_assuming_{role}",
            )
        )

    def _sts(self) -> BaseClient:
        return (
            boto3.client(
                service_name="sts",
                aws_access_key_id=self._session_token.accessKeyId,
                aws_secret_access_key=self._session_token.secretAccessKey,
                aws_session_token=self._session_token.sessionToken,
            )
            if self._session_token
            else boto3.client(service_name="sts")
        )
