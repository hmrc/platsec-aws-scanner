from typing import Any, Iterable, Optional


class AwsScannerException(Exception):
    pass


class AddPartitionException(AwsScannerException):
    pass


class ClientFactoryException(AwsScannerException):
    pass


class CreateDatabaseException(AwsScannerException):
    pass


class CreateTableException(AwsScannerException):
    pass


class DropDatabaseException(AwsScannerException):
    pass


class DropTableException(AwsScannerException):
    pass


class EC2Exception(AwsScannerException):
    pass


class GetQueryResultsException(AwsScannerException):
    pass


class IamException(AwsScannerException):
    pass


class CostExplorerException(AwsScannerException):
    pass


class HostedZonesException(AwsScannerException):
    pass


class QueryLogException(AwsScannerException):
    pass


class InvalidDataPartitionException(AwsScannerException):
    def __init__(self, partitions: Iterable[Any], retention: int, year: int, month: int, day: Optional[int] = None):
        super().__init__(
            (
                f"invalid partition ({year}, {month}{', ' + str(day) if day else ''}). Should be one of "
                f"{sorted(partitions, reverse=True)}. Retention {retention} days."
            )
        )


class InvalidRegionException(AwsScannerException):
    def __init__(self, region: str, regions: Iterable[str]):
        super().__init__(f"invalid region '{region}'. Should be one of {regions}.")


class KmsException(AwsScannerException):
    pass


class ListTablesException(AwsScannerException):
    pass


class ListSSMParametersException(AwsScannerException):
    pass


class GetSSMDocumentException(AwsScannerException):
    pass


class LogsException(AwsScannerException):
    pass


class ResolverException(AwsScannerException):
    pass


class RunQueryException(AwsScannerException):
    pass


class TimeoutException(AwsScannerException):
    pass


class UnknownQueryStateException(AwsScannerException):
    pass


class UnsupportedClientException(AwsScannerException):
    pass


class UnsupportedPolicyDocumentElement(AwsScannerException):
    pass


class UnsupportedTaskException(AwsScannerException):
    pass
