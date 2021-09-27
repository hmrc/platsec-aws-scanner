from json import dumps
from typing import Any


def to_json(obj: Any) -> str:
    return dumps(obj, default=lambda o: {k: v for k, v in vars(o).items() if _is_public(k) and v and not callable(v)})


def _is_public(prop: str) -> bool:
    return not prop.startswith("_")
