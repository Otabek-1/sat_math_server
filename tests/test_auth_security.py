import hashlib
import hmac
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi import HTTPException

SERVER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))

import os

os.environ["BOT_TOKEN"] = "123456:test-token"
os.environ["DATABASE_URL"] = "postgresql+psycopg://test:test@127.0.0.1/test"
os.environ["JWT_SECRET"] = "test-jwt-secret"
os.environ["INTERNAL_API_SECRET"] = "test-internal-secret"

import main as backend


def signed_init_data(auth_date, user=None):
    values = {
        "auth_date": str(auth_date),
        "user": json.dumps(user or {"id": 42, "first_name": "Test"}, separators=(",", ":")),
    }
    check = "\n".join(f"{key}={values[key]}" for key in sorted(values))
    secret = hmac.new(b"WebAppData", backend.BOT_TOKEN.encode(), hashlib.sha256).digest()
    values["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(values)


def test_valid_telegram_init_data_returns_verified_user():
    user = backend.verify_telegram_init_data(signed_init_data(int(time.time())))
    assert user["id"] == 42


def test_tampered_telegram_init_data_is_rejected():
    data = signed_init_data(int(time.time())).replace("first_name%22%3A%22Test", "first_name%22%3A%22Evil")
    with pytest.raises(HTTPException) as error:
        backend.verify_telegram_init_data(data)
    assert error.value.status_code == 401


def test_expired_telegram_init_data_is_rejected():
    with pytest.raises(HTTPException) as error:
        backend.verify_telegram_init_data(signed_init_data(int(time.time()) - backend.TELEGRAM_AUTH_MAX_AGE - 1))
    assert error.value.status_code == 400


def test_password_hash_uses_unique_salt_and_verifies():
    first, salt = backend.hash_password("safe-passphrase")
    second, other_salt = backend.hash_password("safe-passphrase")
    assert salt != other_salt
    assert first != second
    assert hmac.compare_digest(first, backend.hash_password("safe-passphrase", salt)[0])
    assert not hmac.compare_digest(first, backend.hash_password("wrong-passphrase", salt)[0])


def test_email_claim_is_serialized_and_checks_existing_accounts():
    class ResultStub:
        def first(self):
            return "existing-user"

    class ConnectionStub:
        def __init__(self):
            self.statements = []

        def execute(self, statement, params):
            self.statements.append((str(statement), params))
            return ResultStub()

    connection = ConnectionStub()
    assert backend.lock_and_check_email(connection, "person@example.com") == "existing-user"
    assert "pg_advisory_xact_lock" in connection.statements[0][0]
    assert "lower(btrim(email))" in connection.statements[1][0]


def test_email_claim_can_exclude_the_current_account():
    class ResultStub:
        def first(self):
            return None

    class ConnectionStub:
        def __init__(self):
            self.statement = None
            self.params = None

        def execute(self, statement, params):
            self.statement, self.params = str(statement), params
            return ResultStub()

    connection = ConnectionStub()
    assert backend.lock_and_check_email(connection, "person@example.com", "00000000-0000-0000-0000-000000000001") is None
    assert "id <> CAST(:user_id AS UUID)" in connection.statement


def test_sat_scoring_keeps_math_and_reading_writing_raw_scores_separate():
    questions = [
        {"id": "m1", "section": "math", "answer": "4"},
        {"id": "r1", "section": "reading_writing", "answer": "B"},
        {"id": "m2", "section": "math", "answer": "7"},
    ]
    from platform_api import score_answers
    assert score_answers(questions, {"m1": " 4 ", "r1": "b", "m2": "wrong"}) == (1, 1)


def test_student_question_view_does_not_leak_answer_key():
    from platform_api import student_question
    view = student_question({"id": "q1", "prompt": "x", "answer": "secret", "explanation": "secret explanation"})
    assert view == {"id": "q1", "prompt": "x"}


def test_question_hash_is_stable_for_same_content():
    from platform_api import QuestionWrite, question_fingerprint, validate_question
    question = QuestionWrite(kind="mcq", section="math", prompt="  2 + 2? ", choices=["4", "5"], answer="4")
    choices = validate_question(question)
    assert question_fingerprint(question, choices) == question_fingerprint(question, choices)


def test_role_guard_rejects_student_admin_actions():
    from fastapi import HTTPException
    from platform_api import require_roles
    with pytest.raises(HTTPException) as error:
        require_roles({"role": "student"}, "admin")
    assert error.value.status_code == 403
