from unittest import TestCase

from dataclasses import dataclass
from typing import Callable, Optional

from src.json_serializer import to_json


class TestJsonSerializer(TestCase):
    def test_serialize_exclude_callable_and_none_properties(self) -> None:
        self.assertEqual('{"greetings": "Bonjour!"}', to_json(TestJsonSerializer.TestObject()))

    @dataclass
    class TestObject:
        _secret: str = "I'm private, don't serialise me"
        greetings: str = "Bonjour!"
        empty: Optional[str] = None
        func: Callable[[], str] = lambda: "hello"
