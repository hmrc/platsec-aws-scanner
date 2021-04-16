from json import dumps
from typing import Any


def to_json(obj: Any) -> str:
    return dumps(obj, default=lambda o: {k: v for k, v in vars(o).items() if v is not None})
