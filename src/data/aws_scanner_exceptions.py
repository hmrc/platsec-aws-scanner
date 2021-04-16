from typing import Iterable, Tuple


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


class GetQueryResultsException(AwsScannerException):
    pass


class InvalidDataPartitionException(AwsScannerException):
    def __init__(self, year: int, month: int, partitions: Iterable[Tuple[int, int]], retention: int):
        super().__init__(
            f"invalid partition ({year}, {month}). Should be one of {partitions}. Retention {retention} days."
        )


class ListTablesException(AwsScannerException):
    pass


class ListSSMParametersException(AwsScannerException):
    pass


class RunQueryException(AwsScannerException):
    pass


class TimeoutException(AwsScannerException):
    pass


class UnknownQueryStateException(AwsScannerException):
    pass


class UnsupportedTaskException(AwsScannerException):
    pass
