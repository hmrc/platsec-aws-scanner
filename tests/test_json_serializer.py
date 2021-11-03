import datetime
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

    def test_serialize_datetime(self) -> None:
        self.assertEqual(
            '{"name": "Andy", "born": "2021-11-01T15:30:10"}', to_json(TestJsonSerializer.TestDatetimeObject())
        )

    @dataclass
    class TestDatetimeObject:
        name: str = "Andy"
        born: datetime.datetime = datetime.datetime(2021, 11, 1, 15, 30, 10)
