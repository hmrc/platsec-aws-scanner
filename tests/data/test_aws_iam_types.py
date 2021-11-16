from pytest import raises

from src.data.aws_scanner_exceptions import UnsupportedPolicyDocumentElement

from tests.test_types_generator import policy


def test_policy_doc_equals() -> None:
    single_statement = {
        "Statement": {"Effect": "Allow", "Action": ["a:2", "a:1", "b:2", "b:3", "b:1"], "Resource": ["1", "2"]}
    }
    multi_statements = {
        "Statement": [
            {"Effect": "Allow", "Action": ["b:1", "b:2", "a:2"], "Resource": "1"},
            {"Effect": "Allow", "Action": ["b:1", "b:2"], "Resource": "2"},
            {"Effect": "Allow", "Action": "a:2", "Resource": "2"},
            {"Effect": "Allow", "Action": ["a:1", "b:3"], "Resource": ["2", "1"]},
        ],
    }
    assert policy(document=single_statement).doc_equals(multi_statements)


def test_policy_doc_equals_with_condition() -> None:
    single_statement = {
        "Statement": {"Effect": "Deny", "Action": "e:7", "Resource": ["abc", "def"], "Condition": {"a": {"b": "c"}}},
    }
    multi_statements = {
        "Statement": [
            {"Effect": "Deny", "Action": "e:7", "Resource": "def", "Condition": {"a": {"b": "c"}}},
            {"Effect": "Deny", "Action": "e:7", "Resource": "abc", "Condition": {"a": {"b": "c"}}},
        ],
    }
    assert policy(document=single_statement).doc_equals(multi_statements)


def test_policy_doc_not_equals_when_effect_mismatch() -> None:
    doc_a = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1"}}
    doc_b = {"Statement": {"Effect": "Deny", "Action": "a:1", "Resource": "1"}}
    assert not policy(document=doc_a).doc_equals(doc_b)


def test_policy_doc_not_equals_when_action_mismatch() -> None:
    doc_a = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1"}}
    doc_b = {"Statement": {"Effect": "Allow", "Action": "b:1", "Resource": "1"}}
    assert not policy(document=doc_a).doc_equals(doc_b)


def test_policy_doc_not_equals_when_resource_mismatch() -> None:
    doc_a = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1"}}
    doc_b = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "2"}}
    assert not policy(document=doc_a).doc_equals(doc_b)


def test_policy_doc_not_equals_when_condition_mismatch() -> None:
    doc_a = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1", "Condition": {"banana": 9}}}
    doc_b = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1"}}
    assert not policy(document=doc_a).doc_equals(doc_b)


def test_policy_doc_equals_ignores_sid() -> None:
    doc_a = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1", "Sid": "blue"}}
    doc_b = {"Statement": {"Effect": "Allow", "Action": "a:1", "Resource": "1", "Sid": "gray"}}
    assert policy(document=doc_a).doc_equals(doc_b)


def test_policy_doc_equals_not_action_unsupported() -> None:
    doc = {"Statement": {"Effect": "Allow", "NotAction": "a:1", "Resource": "1"}}
    with raises(UnsupportedPolicyDocumentElement, match="NotAction"):
        policy().doc_equals(doc)


def test_policy_doc_equals_not_resource_unsupported() -> None:
    doc = {"Statement": {"Effect": "Allow", "Action": "a:1", "NotResource": "1"}}
    with raises(UnsupportedPolicyDocumentElement, match="NotResource"):
        policy().doc_equals(doc)


def test_policy_doc_equals_principal_unsupported() -> None:
    doc = {"Statement": {"Effect": "Allow", "Action": "a:1", "Principal": "1"}}
    with raises(UnsupportedPolicyDocumentElement, match="Principal"):
        policy().doc_equals(doc)


def test_policy_doc_equals_not_principal_unsupported() -> None:
    doc = {"Statement": {"Effect": "Allow", "Action": "a:1", "NotPrincipal": "1"}}
    with raises(UnsupportedPolicyDocumentElement, match="NotPrincipal"):
        policy().doc_equals(doc)
