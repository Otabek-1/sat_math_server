"""Manual API integration smoke test; uses and drops an isolated PostgreSQL schema."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import sys
import tempfile
import uuid

from sqlalchemy import create_engine, text
from fastapi.testclient import TestClient

SERVER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))

import main
import platform_api


def expect(response, code, label):
    if response.status_code != code:
        raise AssertionError(f"{label}: HTTP {response.status_code}: {response.text[:400]}")
    return response.json() if response.content else None


def run():
    database_url = os.getenv("PLATFORM_TEST_DATABASE_URL")
    if not database_url:
        raise RuntimeError("Set PLATFORM_TEST_DATABASE_URL to a disposable PostgreSQL database before running this smoke test")
    if database_url == os.getenv("DATABASE_URL"):
        raise RuntimeError("PLATFORM_TEST_DATABASE_URL must point to a separate disposable database, not the application database")
    admin_engine = create_engine(database_url, pool_pre_ping=True)
    schema = "platform_test_" + uuid.uuid4().hex[:12]
    with admin_engine.begin() as connection:
        connection.execute(text(f"CREATE SCHEMA {schema}"))
    isolated_engine = create_engine(database_url, connect_args={"options": f"-csearch_path={schema}"}, pool_pre_ping=True)
    with isolated_engine.connect() as connection:
        active_schema = connection.execute(text("SELECT current_schema()")).scalar_one()
    if active_schema != schema:
        isolated_engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        admin_engine.dispose()
        raise RuntimeError(f"Database ignored the isolated schema (active schema: {active_schema}); refusing to run integration writes")
    upload_dir = Path(tempfile.mkdtemp(prefix="nemis-platform-test-"))
    main.engine = isolated_engine
    platform_api.engine = isolated_engine
    platform_api.UPLOAD_DIR = upload_dir
    platform_api.SUPABASE_URL = ""
    platform_api.SUPABASE_SERVICE_ROLE_KEY = ""
    suffix = uuid.uuid4().hex[:12]
    student_email = f"student-{suffix}@example.com"
    teacher_email = f"teacher-{suffix}@example.com"
    try:
        with TestClient(main.app) as client:
            student = expect(client.post("/api/auth/register", json={"name": "Test Student", "email": student_email, "password": "test-password-123"}), 201, "register student")
            student_auth = {"Authorization": "Bearer " + student["access_token"]}
            telegram_test_id = 700_000_000_000 + uuid.uuid4().int % 100_000_000_000
            with isolated_engine.begin() as connection:
                connection.execute(text("UPDATE users SET telegram_id=:telegram_id WHERE id=CAST(:id AS UUID)"), {"telegram_id": telegram_test_id, "id": student["user"]["id"]})
            expect(client.post("/api/groups", json={"name": "Denied group"}, headers=student_auth), 403, "student authorization")
            teacher_account = expect(client.post("/api/auth/register", json={"name": "Test Teacher", "email": teacher_email, "password": "test-password-123"}), 201, "register teacher account")

            with isolated_engine.begin() as connection:
                connection.execute(text("UPDATE users SET role='teacher',student_id=NULL WHERE id=CAST(:id AS UUID)"), {"id": teacher_account["user"]["id"]})
            teacher = expect(client.post("/api/auth/login", json={"email": teacher_email, "password": "test-password-123"}), 200, "teacher login")
            teacher_auth = {"Authorization": "Bearer " + teacher["access_token"]}
            group = expect(client.post("/api/groups", json={"name": "Test Group", "description": "temporary"}, headers=teacher_auth), 201, "group creation")
            expect(client.post(f"/api/groups/{group['id']}/members", json={"student_id": student["user"]["student_id"]}, headers=teacher_auth), 201, "student assignment")
            question = expect(client.post("/api/questions", json={"kind": "mcq", "section": "math", "prompt": "2+2?", "choices": ["4", "5"], "answer": "4"}, headers=teacher_auth), 201, "MCQ creation")
            listed_questions = expect(client.get("/api/questions", headers=teacher_auth), 200, "question bank listing")
            assert any(item["id"] == question["id"] for item in listed_questions)
            spr = expect(client.post("/api/questions", json={"kind": "spr", "section": "reading_writing", "prompt": "Type B", "answer": "B"}, headers=teacher_auth), 201, "SPR creation")
            expect(client.post("/api/questions", json={"kind": "mcq", "section": "math", "prompt": "2+2?", "choices": ["4", "5"], "answer": "4"}, headers=teacher_auth), 409, "duplicate question rejection")

            assignment = expect(client.post("/api/assignments", json={"group_id": group["id"], "title": "Test assignment", "question_ids": [question["id"], spr["id"]]}, headers=teacher_auth), 201, "draft assignment")
            expect(client.post(f"/api/assignments/{assignment['id']}/publish", headers=teacher_auth), 200, "publish assignment")
            internal_headers = {"X-Internal-Secret": main.INTERNAL_API_SECRET}
            notifications = expect(client.post("/api/internal/notifications/claim", json={"limit": 20}, headers=internal_headers), 200, "bot notification claim")
            assert len(notifications) == 1 and "Test assignment" in notifications[0]["message"]
            expect(client.post("/api/internal/notifications/ack", json={"ids": [notifications[0]["id"]], "delivered": True}, headers=internal_headers), 200, "bot notification acknowledge")
            questions = expect(client.get(f"/api/assignments/{assignment['id']}/questions", headers=student_auth), 200, "student question access")
            assert len(questions) == 2 and "answer" not in questions[0]
            submitted = expect(client.post(f"/api/assignments/{assignment['id']}/submit", json={"answers": {question["id"]: "4", spr["id"]: "b"}}, headers=student_auth), 200, "assignment submission")
            assert (submitted["raw_math"], submitted["raw_reading_writing"]) == (1, 1)

            mock = expect(client.post("/api/mocks", json={"title": "Test mock", "question_ids": [question["id"], spr["id"]], "group_ids": [group["id"]]}, headers=teacher_auth), 201, "mock creation")
            expect(client.post(f"/api/mocks/{mock['id']}/open", headers=teacher_auth), 200, "open mock")
            attempt = expect(client.post(f"/api/mocks/{mock['id']}/attempts", json={"answers": {question["id"]: "4", spr["id"]: "B"}}, headers=student_auth), 201, "mock attempt")
            expect(client.post(f"/api/mocks/{mock['id']}/close", headers=teacher_auth), 200, "close mock")
            reopened = expect(client.post(f"/api/mocks/{mock['id']}/reopen", json={"deadline": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}, headers=teacher_auth), 200, "reopen mock")
            assert reopened["status"] == "open"
            results = expect(client.get(f"/api/mocks/{mock['id']}/results", headers=teacher_auth), 200, "mock results")
            assert len(results) == 1 and results[0]["id"] == attempt["id"]

            lesson = expect(client.post("/api/lessons", json={"group_id": group["id"], "title": "Test lesson", "content": "Lesson"}, headers=teacher_auth), 201, "lesson creation")
            expect(client.patch(f"/api/lessons/{lesson['id']}", json={"group_id": group["id"], "title": "Edited lesson", "content": "Updated"}, headers=teacher_auth), 200, "lesson draft edit")
            expect(client.post(f"/api/lessons/{lesson['id']}/publish", headers=teacher_auth), 200, "lesson publish")
            expect(client.post("/api/posts", json={"group_id": group["id"], "body": "Test notice"}, headers=teacher_auth), 201, "post create")

            resource = expect(client.post("/api/resources", files={"file": ("private.txt", b"protected test file", "text/plain")}, headers=teacher_auth), 201, "protected file upload")
            expect(client.post(f"/api/resources/{resource['id']}/link", json={"target_type": "group", "target_id": group["id"]}, headers=teacher_auth), 201, "resource link")
            download = client.get(f"/api/resources/{resource['id']}/download", headers=student_auth)
            if download.status_code != 200:
                raise AssertionError(f"authorized download: HTTP {download.status_code}: {download.text[:400]}")
            assert download.content == b"protected test file"
            denied = client.get(f"/api/resources/{resource['id']}/download")
            assert denied.status_code == 401
        print("Platform integration smoke passed: auth/roles, groups, MCQ/SPR, duplicate question guard, assignment scoring, mock attempts/reopen/history, lessons, posts, protected uploads/access.")
    finally:
        isolated_engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f"DROP SCHEMA {schema} CASCADE"))
        admin_engine.dispose()
        shutil.rmtree(upload_dir, ignore_errors=True)


if __name__ == "__main__":
    run()
