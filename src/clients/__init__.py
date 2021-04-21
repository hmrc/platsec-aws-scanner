from logging import getLogger
from typing import Callable, Type, TypeVar

from botocore.exceptions import BotoCoreError, ClientError

T = TypeVar("T")


def boto_try(boto_function: Callable[[], T], default: Type[T], except_msg: str) -> T:
    try:
        return boto_function()
    except (BotoCoreError, ClientError) as error:
        getLogger().warning(f"{except_msg}: {error}")
        return default()
