from typing import Any, List

SERVICE_ACCOUNT_USER = "__lambda"
SERVICE_ACCOUNT_TOKEN = "000000"
DEFAULT_REGION = "eu-west-2"


def is_list(target: Any) -> bool:
    return issubclass(type(target), List)
