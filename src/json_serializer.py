import datetime
from json import dumps
from typing import Any


def to_json(obj: Any) -> str:
    return dumps(
        obj,
        default=lambda o: {
            k: _datetime_to_string(v) for k, v in vars(o).items() if _is_public(k) and v is not None and not callable(v)
        },
    )


def _is_public(prop: str) -> bool:
    return not prop.startswith("_")


def _datetime_to_string(o: Any) -> Any:
    if isinstance(o, datetime.datetime):
        return o.isoformat()
    else:
        return o
