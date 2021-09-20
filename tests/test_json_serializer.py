from tests.aws_scanner_test_case import AwsScannerTestCase

from dataclasses import dataclass
from typing import Callable, Optional

from src.json_serializer import to_json


class TestJsonSerializer(AwsScannerTestCase):
    def test_serialize_exclude_callable_and_none_properties(self) -> None:
        self.assertEqual('{"greetings": "Bonjour!"}', to_json(TestJsonSerializer.TestObject()))

    @dataclass
    class TestObject:
        greetings: str = "Bonjour!"
        empty: Optional[str] = None
        func: Callable[[], str] = lambda: "hello"
