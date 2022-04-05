from typing import Any, Dict, Sequence

from src.data.aws_task_report import AwsTaskReport

SEPARATOR = ","
NEW_LINE = "\n"


def to_csv(reports: Sequence[AwsTaskReport]) -> str:
    """
    This converts task reports to CSV.
    Admittedly, it's rough over the edges and will require some work to handle all possible report types.
    Shield eyes from light.
    :param reports: a collection of task reports to be converted to CSV format
    :return: CSV string representation of task reports
    """
    return f"{_headers(reports)}{NEW_LINE}{_rows(reports)}"


def _headers(reports: Sequence[AwsTaskReport]) -> str:
    default_headers = f"account_id{SEPARATOR}account_name"
    specific_headers = _results_headers(next(iter(reports)).results) if reports else ""
    return f"{default_headers}{f'{SEPARATOR}{specific_headers}' if specific_headers else ''}"


def _results_headers(results: Dict[Any, Any]) -> str:
    obj = next(iter(next(iter(results.values()), [])), None)
    return SEPARATOR.join([f"{type(obj).__name__.lower()}_{name}" for name, _ in vars(obj).items()]) if obj else ""


def _rows(reports: Sequence[AwsTaskReport]) -> str:
    return NEW_LINE.join([_result_rows(report) for report in reports])


def _result_rows(report: AwsTaskReport) -> str:
    return NEW_LINE.join([f"{_account(report)}{SEPARATOR}{_obj_row(o)}" for _, v in report.results.items() for o in v])


def _account(report: AwsTaskReport) -> str:
    return SEPARATOR.join([report.account.identifier, report.account.name])


def _obj_row(obj: Any) -> str:
    return SEPARATOR.join([str(val) for _, val in vars(obj).items()])
