import json
import hashlib
import hmac
import math
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import httpx

from main import INTERNAL_API_SECRET, engine, get_current_user

router = APIRouter(prefix="/api")
UPLOAD_DIR = Path(os.getenv("PRIVATE_UPLOAD_DIR", Path(__file__).resolve().parent / "private_uploads"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(10 * 1024 * 1024)))
ALLOWED_UPLOAD_TYPES = {"application/pdf", "image/png", "image/jpeg", "image/webp", "text/plain"}
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_STORAGE_BUCKET = os.getenv("SUPABASE_STORAGE_BUCKET", "platform-resources")
ROLES = {"student", "teacher", "admin", "super_admin"}

SCHEMA = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'student'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS student_id TEXT",
    "CREATE UNIQUE INDEX IF NOT EXISTS users_student_id_unique ON users(student_id) WHERE student_id IS NOT NULL",
    """CREATE TABLE IF NOT EXISTS groups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
        created_by UUID NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS group_teachers (
        group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE, teacher_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(group_id,teacher_id))""",
    """CREATE TABLE IF NOT EXISTS group_members (
        group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE, student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        added_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(group_id,student_id))""",
    """CREATE TABLE IF NOT EXISTS taxonomies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), section TEXT NOT NULL CHECK(section IN ('math','reading_writing')),
        domain TEXT NOT NULL, skill TEXT NOT NULL, created_by UUID REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(section,domain,skill))""",
    """CREATE TABLE IF NOT EXISTS questions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), owner_id UUID NOT NULL REFERENCES users(id), kind TEXT NOT NULL CHECK(kind IN ('mcq','spr')),
        section TEXT NOT NULL CHECK(section IN ('math','reading_writing')), prompt TEXT NOT NULL, choices JSONB NOT NULL DEFAULT '[]'::jsonb,
        answer TEXT NOT NULL, explanation TEXT NOT NULL DEFAULT '', image_url TEXT, taxonomy_id UUID REFERENCES taxonomies(id) ON DELETE SET NULL,
        is_active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    "CREATE INDEX IF NOT EXISTS questions_owner_idx ON questions(owner_id,created_at DESC)",
    "ALTER TABLE questions ADD COLUMN IF NOT EXISTS content_hash TEXT",
    "CREATE UNIQUE INDEX IF NOT EXISTS questions_owner_content_unique ON questions(owner_id,content_hash) WHERE content_hash IS NOT NULL",
    "ALTER TABLE questions ADD COLUMN IF NOT EXISTS difficulty TEXT NOT NULL DEFAULT 'medium'",
    "ALTER TABLE questions DROP CONSTRAINT IF EXISTS questions_difficulty_check",
    "ALTER TABLE questions ADD CONSTRAINT questions_difficulty_check CHECK(difficulty IN ('easy','medium','hard'))",
    """CREATE TABLE IF NOT EXISTS assignments (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), teacher_id UUID NOT NULL REFERENCES users(id), group_id UUID NOT NULL REFERENCES groups(id),
        title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', question_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published','closed')), deadline TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS assignment_submissions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), assignment_id UUID NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
        student_id UUID NOT NULL REFERENCES users(id), answers JSONB NOT NULL DEFAULT '{}'::jsonb, raw_score INTEGER NOT NULL DEFAULT 0,
        total_questions INTEGER NOT NULL DEFAULT 0, submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(assignment_id,student_id))""",
    "ALTER TABLE assignments ADD COLUMN IF NOT EXISTS selection_rules JSONB NOT NULL DEFAULT '[]'::jsonb",
    """CREATE TABLE IF NOT EXISTS assignment_question_sets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), assignment_id UUID NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
        student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, question_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(assignment_id,student_id))""",
    """CREATE TABLE IF NOT EXISTS mocks (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), owner_id UUID NOT NULL REFERENCES users(id), title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '', question_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','open','closed')), opens_at TIMESTAMPTZ, deadline TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS mock_targets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), mock_id UUID NOT NULL REFERENCES mocks(id) ON DELETE CASCADE,
        group_id UUID REFERENCES groups(id) ON DELETE CASCADE, user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        CHECK ((group_id IS NULL) <> (user_id IS NULL)))""",
    "CREATE UNIQUE INDEX IF NOT EXISTS mock_target_group_unique ON mock_targets(mock_id,group_id) WHERE group_id IS NOT NULL",
    "CREATE UNIQUE INDEX IF NOT EXISTS mock_target_user_unique ON mock_targets(mock_id,user_id) WHERE user_id IS NOT NULL",
    "ALTER TABLE mocks ADD COLUMN IF NOT EXISTS selection_rules JSONB NOT NULL DEFAULT '[]'::jsonb",
    """CREATE TABLE IF NOT EXISTS mock_question_sets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), mock_id UUID NOT NULL REFERENCES mocks(id) ON DELETE CASCADE,
        student_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, question_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(mock_id,student_id))""",
    """CREATE TABLE IF NOT EXISTS mock_attempts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), mock_id UUID NOT NULL REFERENCES mocks(id), student_id UUID NOT NULL REFERENCES users(id),
        attempt_number INTEGER NOT NULL, answers JSONB NOT NULL DEFAULT '{}'::jsonb, raw_math INTEGER NOT NULL DEFAULT 0,
        raw_reading_writing INTEGER NOT NULL DEFAULT 0, total_questions INTEGER NOT NULL DEFAULT 0,
        submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(mock_id,student_id,attempt_number))""",
    """CREATE TABLE IF NOT EXISTS resources (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), owner_id UUID NOT NULL REFERENCES users(id), filename TEXT NOT NULL,
        content_type TEXT NOT NULL, size_bytes BIGINT NOT NULL, storage_path TEXT NOT NULL UNIQUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS resource_links (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), resource_id UUID NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
        target_type TEXT NOT NULL CHECK(target_type IN ('group','assignment','post','lesson')), target_id UUID NOT NULL,
        created_by UUID NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), UNIQUE(resource_id,target_type,target_id))""",
    """CREATE TABLE IF NOT EXISTS lessons (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), teacher_id UUID NOT NULL REFERENCES users(id), group_id UUID NOT NULL REFERENCES groups(id),
        title TEXT NOT NULL, content TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS posts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), author_id UUID NOT NULL REFERENCES users(id), group_id UUID NOT NULL REFERENCES groups(id),
        body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS platform_settings (
        key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_by UUID REFERENCES users(id), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY, actor_id UUID REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL,
        target_type TEXT NOT NULL, target_id TEXT, metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS notification_outbox (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, claimed_until TIMESTAMPTZ,
        delivered_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    """CREATE TABLE IF NOT EXISTS calibration_jobs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(), created_by UUID NOT NULL REFERENCES users(id), name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','completed','failed')),
        response_matrix JSONB NOT NULL, calibration JSONB, label TEXT NOT NULL DEFAULT 'experimental_estimate',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), completed_at TIMESTAMPTZ)""",
]


def init_platform_schema(connection):
    for statement in SCHEMA:
        connection.execute(text(statement))
    connection.execute(text("INSERT INTO platform_settings(key,value) VALUES ('registration_enabled','true'::jsonb) ON CONFLICT(key) DO NOTHING"))
    connection.execute(text("UPDATE users SET student_id='STU-' || upper(substr(replace(id::text,'-',''),1,10)) WHERE role='student' AND student_id IS NULL"))


def public_row(row):
    return dict(row) if row else None


def require_roles(user, *roles):
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Bu amal uchun ruxsat yo‘q")


def is_admin(user):
    return user.get("role") in {"admin", "super_admin"}


def audit(connection, actor, action, target_type, target_id=None, metadata=None):
    connection.execute(text("INSERT INTO audit_logs(actor_id,action,target_type,target_id,metadata) VALUES (CAST(:actor AS UUID),:action,:kind,:target,CAST(:meta AS JSONB))"),
        {"actor": str(actor["id"]), "action": action, "kind": target_type, "target": str(target_id) if target_id else None, "meta": json.dumps(metadata or {})})


def enqueue_group_message(connection, group_id, message):
    connection.execute(text("INSERT INTO notification_outbox(user_id,message) SELECT u.id,:message FROM group_members gm JOIN users u ON u.id=gm.student_id WHERE gm.group_id=CAST(:gid AS UUID) AND u.telegram_id IS NOT NULL AND u.is_active"), {"gid": str(group_id), "message": message[:4000]})


def group_allowed(connection, user, group_id, write=False):
    if is_admin(user):
        return True
    if user.get("role") == "teacher":
        return connection.execute(text("SELECT 1 FROM group_teachers WHERE group_id=CAST(:gid AS UUID) AND teacher_id=CAST(:uid AS UUID)"), {"gid": str(group_id), "uid": str(user["id"])}).first() is not None
    if user.get("role") == "student" and not write:
        return connection.execute(text("SELECT 1 FROM group_members WHERE group_id=CAST(:gid AS UUID) AND student_id=CAST(:uid AS UUID)"), {"gid": str(group_id), "uid": str(user["id"])}).first() is not None
    return False


def teacher_can_manage_mock(connection,user,mock):
    if is_admin(user) or str(mock["owner_id"])==str(user["id"]):return True
    if user.get("role")!="teacher":return False
    return connection.execute(text("""SELECT 1 FROM mock_targets mt JOIN group_teachers gt ON gt.group_id=mt.group_id
      WHERE mt.mock_id=CAST(:mid AS UUID) AND gt.teacher_id=CAST(:uid AS UUID) LIMIT 1"""),{"mid":str(mock["id"]),"uid":str(user["id"])}).first() is not None


def question_rows(connection, question_ids, user=None):
    if not isinstance(question_ids, list) or not question_ids:
        raise HTTPException(status_code=422, detail="Kamida bitta savol tanlang")
    try:
        ids = [str(uuid.UUID(str(item))) for item in question_ids]
    except ValueError:
        raise HTTPException(status_code=422, detail="Savol ID yaroqsiz")
    if len(set(ids)) != len(ids):raise HTTPException(status_code=422,detail="Bir savol bir vazifaga ikki marta qo‘shilgan")
    rows = connection.execute(text("SELECT q.*,t.section AS taxonomy_section FROM questions q LEFT JOIN taxonomies t ON t.id=q.taxonomy_id WHERE q.id=ANY(CAST(:ids AS UUID[])) AND q.is_active"), {"ids": ids}).mappings().all()
    by_id = {str(row["id"]): dict(row) for row in rows}
    if len(by_id) != len(set(ids)):
        raise HTTPException(status_code=422, detail="Savollardan biri topilmadi")
    selected = [by_id[item] for item in ids]
    return selected


def score_answers(questions, answers):
    if not isinstance(answers, dict):
        raise HTTPException(status_code=422, detail="Javoblar obyekt ko‘rinishida bo‘lishi kerak")
    ids = {str(q["id"]) for q in questions}
    if set(answers) - ids:
        raise HTTPException(status_code=422, detail="Javoblar ichida bu topshiriqqa kirmaydigan savollar bor")
    math_score = rw_score = 0
    for q in questions:
        submitted = str(answers.get(str(q["id"]), "")).strip().casefold()
        correct = submitted == str(q["answer"]).strip().casefold()
        if correct:
            if q["section"] == "math":
                math_score += 1
            else:
                rw_score += 1
    return math_score, rw_score


def student_question(question):
    item = dict(question)
    item.pop("answer", None)
    item.pop("explanation", None)
    return item


class GroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str = Field(default="", max_length=2000)
    teacher_ids: list[str] = Field(default_factory=list)


class GroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


class MemberAdd(BaseModel):
    student_id: str = Field(min_length=3, max_length=40)


class TeacherAdd(BaseModel):
    teacher_id: str


class QuestionWrite(BaseModel):
    kind: str
    section: str
    prompt: str = Field(min_length=1, max_length=12000)
    choices: list[str] = Field(default_factory=list, max_length=8)
    answer: str = Field(min_length=1, max_length=1000)
    explanation: str = Field(default="", max_length=12000)
    image_url: HttpUrl | None = None
    taxonomy_id: str | None = None
    difficulty: str = "medium"


class SelectionRule(BaseModel):
    count: int = Field(ge=1, le=100)
    section: str = "math"
    difficulty: str = "medium"
    taxonomy_id: str | None = None
    kind: str | None = None


class AssignmentWrite(BaseModel):
    group_id: str
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=6000)
    question_ids: list[str] = Field(default_factory=list)
    selection_rules: list[SelectionRule] = Field(default_factory=list)
    deadline: datetime | None = None


class SubmissionWrite(BaseModel):
    answers: dict[str, str]


class MockWrite(BaseModel):
    title: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=6000)
    question_ids: list[str] = Field(default_factory=list)
    selection_rules: list[SelectionRule] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    student_ids: list[str] = Field(default_factory=list)
    opens_at: datetime | None = None
    deadline: datetime | None = None


class ReopenWrite(BaseModel):
    deadline: datetime


class LessonWrite(BaseModel):
    group_id: str
    title: str = Field(min_length=2, max_length=200)
    content: str = Field(default="", max_length=30000)


class TaxonomyWrite(BaseModel):
    section: str
    domain: str = Field(min_length=1, max_length=120)
    skill: str = Field(min_length=1, max_length=160)


class RoleUpdate(BaseModel):
    role: str


class ActiveUpdate(BaseModel):
    is_active: bool


class SettingUpdate(BaseModel):
    value: bool


class LinkResource(BaseModel):
    target_type: str
    target_id: str


class PostWrite(BaseModel):
    group_id: str
    body: str = Field(min_length=1, max_length=6000)


class NotificationClaim(BaseModel):
    limit: int = Field(default=20, ge=1, le=50)


class NotificationAck(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=50)
    delivered: bool


def verify_internal_secret(secret):
    if not secret or not hmac.compare_digest(secret, INTERNAL_API_SECRET):
        raise HTTPException(status_code=401, detail="Internal API authorization failed")


@router.post("/internal/notifications/claim")
def claim_notifications(payload:NotificationClaim,x_internal_secret:str=Header(...)):
    verify_internal_secret(x_internal_secret)
    with engine.begin() as c:
        rows=c.execute(text("""SELECT n.id,n.user_id,u.telegram_id,n.message,n.attempts FROM notification_outbox n
          JOIN users u ON u.id=n.user_id WHERE n.delivered_at IS NULL AND n.attempts<5 AND (n.claimed_until IS NULL OR n.claimed_until<NOW())
          AND u.telegram_id IS NOT NULL AND u.is_active ORDER BY n.created_at LIMIT :limit FOR UPDATE OF n SKIP LOCKED"""),{"limit":payload.limit}).mappings().all()
        ids=[str(r["id"]) for r in rows]
        if ids:c.execute(text("UPDATE notification_outbox SET attempts=attempts+1,claimed_until=NOW()+INTERVAL '90 seconds' WHERE id=ANY(CAST(:ids AS UUID[]))"),{"ids":ids})
    return [{"id":str(r["id"]),"telegram_id":r["telegram_id"],"message":r["message"],"attempt":r["attempts"]+1} for r in rows]


@router.post("/internal/notifications/ack")
def ack_notifications(payload:NotificationAck,x_internal_secret:str=Header(...)):
    verify_internal_secret(x_internal_secret)
    if not payload.ids:return {"updated":0}
    with engine.begin() as c:
        if payload.delivered:
            result=c.execute(text("UPDATE notification_outbox SET delivered_at=NOW(),claimed_until=NULL WHERE id=ANY(CAST(:ids AS UUID[])) AND delivered_at IS NULL"),{"ids":payload.ids})
        else:
            result=c.execute(text("UPDATE notification_outbox SET claimed_until=NOW()+INTERVAL '30 seconds' WHERE id=ANY(CAST(:ids AS UUID[])) AND delivered_at IS NULL"),{"ids":payload.ids})
    return {"updated":result.rowcount}


@router.get("/dashboard")
def dashboard(user=Depends(get_current_user)):
    with engine.connect() as c:
        groups = c.execute(text("""SELECT COUNT(*) FROM groups g WHERE :admin OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=g.id AND gt.teacher_id=CAST(:uid AS UUID)) OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.student_id=CAST(:uid AS UUID))"""), {"admin": is_admin(user), "uid": str(user["id"])}).scalar_one()
        questions = c.execute(text("SELECT COUNT(*) FROM questions WHERE is_active AND (:admin OR owner_id=CAST(:uid AS UUID))"), {"admin": is_admin(user), "uid": str(user["id"])}).scalar_one()
        assignments = c.execute(text("""SELECT COUNT(*) FROM assignments a WHERE a.status='published' AND
          (:admin OR (CAST(:role AS TEXT)='teacher' AND (a.teacher_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=a.group_id AND gt.teacher_id=CAST(:uid AS UUID)))) OR
          EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=a.group_id AND gm.student_id=CAST(:uid AS UUID)))"""), {"admin": is_admin(user), "role": user["role"], "uid": str(user["id"])}).scalar_one()
        attempts = c.execute(text("SELECT COUNT(*) FROM mock_attempts WHERE student_id=CAST(:uid AS UUID)"), {"uid": str(user["id"])}).scalar_one()
    return {"role": user["role"], "groups": groups, "questions": questions, "published_assignments": assignments, "mock_attempts": attempts}


@router.get("/groups")
def list_groups(user=Depends(get_current_user)):
    with engine.connect() as c:
        rows = c.execute(text("""SELECT g.*, (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id=g.id) AS student_count
          FROM groups g WHERE :admin OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=g.id AND gt.teacher_id=CAST(:uid AS UUID))
          OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=g.id AND gm.student_id=CAST(:uid AS UUID)) ORDER BY g.created_at DESC"""), {"admin": is_admin(user), "uid": str(user["id"])}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/groups", status_code=201)
def create_group(payload: GroupCreate, user=Depends(get_current_user)):
    require_roles(user, "teacher", "admin", "super_admin")
    with engine.begin() as c:
        result = c.execute(text("INSERT INTO groups(name,description,created_by) VALUES (:name,:description,CAST(:uid AS UUID)) RETURNING *"), {"name": payload.name.strip(), "description": payload.description, "uid": str(user["id"])})
        group = result.mappings().first()
        teacher_ids = set(payload.teacher_ids)
        if user["role"] == "teacher": teacher_ids.add(str(user["id"]))
        if teacher_ids and not is_admin(user) and teacher_ids - {str(user["id"])}:
            raise HTTPException(status_code=403, detail="O‘qituvchi faqat o‘zini guruhga biriktirishi mumkin")
        for teacher_id in teacher_ids:
            valid=c.execute(text("SELECT id FROM users WHERE id=CAST(:tid AS UUID) AND role='teacher' AND is_active"),{"tid":teacher_id}).first()
            if not valid:raise HTTPException(status_code=422,detail="Guruhga tayinlanadigan faol o‘qituvchi topilmadi")
            c.execute(text("INSERT INTO group_teachers(group_id,teacher_id) VALUES(CAST(:gid AS UUID),CAST(:tid AS UUID))"), {"gid": str(group["id"]), "tid": teacher_id})
        audit(c, user, "group_created", "group", group["id"], {"name": payload.name})
    return public_row(group)


@router.patch("/groups/{group_id}")
def update_group(group_id: str, payload: GroupUpdate, user=Depends(get_current_user)):
    with engine.begin() as c:
        if not group_allowed(c, user, group_id, write=True): raise HTTPException(status_code=404, detail="Guruh topilmadi")
        group = c.execute(text("UPDATE groups SET name=COALESCE(:name,name),description=COALESCE(:description,description),updated_at=NOW() WHERE id=CAST(:gid AS UUID) RETURNING *"), {"name": payload.name.strip() if payload.name else None, "description": payload.description, "gid": group_id}).mappings().first()
    return public_row(group)


@router.get("/groups/{group_id}/members")
def group_members(group_id: str, user=Depends(get_current_user)):
    with engine.connect() as c:
        if not group_allowed(c, user, group_id): raise HTTPException(status_code=404, detail="Guruh topilmadi")
        rows = c.execute(text("SELECT u.id,u.student_id,u.first_name,u.last_name,u.email FROM users u JOIN group_members gm ON gm.student_id=u.id WHERE gm.group_id=CAST(:gid AS UUID) ORDER BY u.first_name"), {"gid": group_id}).mappings().all()
    return [public_row(r) for r in rows]


@router.get("/groups/{group_id}/teachers")
def group_teachers(group_id:str,user=Depends(get_current_user)):
    with engine.connect() as c:
        if not group_allowed(c,user,group_id,write=True):raise HTTPException(status_code=404,detail="Guruh topilmadi")
        rows=c.execute(text("SELECT u.id,u.first_name,u.email FROM group_teachers gt JOIN users u ON u.id=gt.teacher_id WHERE gt.group_id=CAST(:gid AS UUID) ORDER BY u.first_name"),{"gid":group_id}).mappings().all()
    return [public_row(r) for r in rows]


@router.get("/teachers")
def list_teachers(user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.connect() as c:rows=c.execute(text("SELECT id,first_name,email FROM users WHERE role='teacher' AND is_active ORDER BY first_name,email")).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/groups/{group_id}/teachers",status_code=201)
def assign_group_teacher(group_id:str,payload:TeacherAdd,user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.begin() as c:
        teacher=c.execute(text("SELECT id FROM users WHERE id=CAST(:id AS UUID) AND role='teacher' AND is_active"),{"id":payload.teacher_id}).first()
        if not teacher:raise HTTPException(status_code=404,detail="Faol o‘qituvchi topilmadi")
        try:c.execute(text("INSERT INTO group_teachers(group_id,teacher_id) VALUES(CAST(:gid AS UUID),CAST(:tid AS UUID))"),{"gid":group_id,"tid":payload.teacher_id})
        except IntegrityError:raise HTTPException(status_code=409,detail="O‘qituvchi guruhga avval tayinlangan")
        audit(c,user,"teacher_assigned_to_group","group",group_id,{"teacher_id":payload.teacher_id})
    return {"status":"assigned"}


@router.post("/groups/{group_id}/members", status_code=201)
def add_group_member(group_id: str, payload: MemberAdd, user=Depends(get_current_user)):
    with engine.begin() as c:
        if not group_allowed(c, user, group_id, write=True): raise HTTPException(status_code=404, detail="Guruh topilmadi")
        student = c.execute(text("SELECT id FROM users WHERE student_id=:sid AND role='student' AND is_active"), {"sid": payload.student_id.strip()}).first()
        if not student: raise HTTPException(status_code=404, detail="Student ID bo‘yicha faol o‘quvchi topilmadi")
        try:
            c.execute(text("INSERT INTO group_members(group_id,student_id,added_by) VALUES (CAST(:gid AS UUID),CAST(:sid AS UUID),CAST(:actor AS UUID))"), {"gid": group_id, "sid": str(student[0]), "actor": str(user["id"])})
        except IntegrityError:
            raise HTTPException(status_code=409, detail="O‘quvchi bu guruhga avval qo‘shilgan")
    return {"status": "added"}


@router.delete("/groups/{group_id}/members/{student_id}")
def remove_group_member(group_id: str, student_id: str, user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        if not group_allowed(c,user,group_id,write=True):raise HTTPException(status_code=404,detail="Guruh topilmadi")
        removed=c.execute(text("DELETE FROM group_members gm USING users u WHERE gm.group_id=CAST(:gid AS UUID) AND gm.student_id=u.id AND u.student_id=:sid RETURNING gm.student_id"),{"gid":group_id,"sid":student_id}).first()
        if not removed:raise HTTPException(status_code=404,detail="O‘quvchi guruhda topilmadi")
        audit(c,user,"group_student_removed","group",group_id,{"student_id":student_id})
    return {"status":"removed"}


@router.get("/students/search")
def search_student(student_id: str = Query(min_length=3, max_length=40), group_id: str | None = None, user=Depends(get_current_user)):
    require_roles(user, "teacher", "admin", "super_admin")
    with engine.connect() as c:
        if group_id and not group_allowed(c, user, group_id, write=True): raise HTTPException(status_code=404, detail="Guruh topilmadi")
        row = c.execute(text("SELECT id,student_id,first_name,last_name,email FROM users WHERE student_id=:sid AND role='student' AND is_active"), {"sid": student_id.strip()}).mappings().first()
    if not row: raise HTTPException(status_code=404, detail="Student ID topilmadi")
    return public_row(row)


@router.get("/questions")
def list_questions(section: str | None = None, kind: str | None = None, taxonomy_id: str | None = None, user=Depends(get_current_user)):
    require_roles(user, "teacher", "admin", "super_admin")
    clauses = ["q.is_active"]
    params = {}
    if section is not None:
        if section not in {"math", "reading_writing"}:
            raise HTTPException(status_code=422, detail="Savol bo‘limi noto‘g‘ri")
        clauses.append("q.section=:section")
        params["section"] = section
    if kind is not None:
        if kind not in {"mcq", "spr"}:
            raise HTTPException(status_code=422, detail="Savol turi noto‘g‘ri")
        clauses.append("q.kind=:kind")
        params["kind"] = kind
    if taxonomy_id is not None:
        try:
            params["taxonomy_id"] = str(uuid.UUID(taxonomy_id))
        except ValueError:
            raise HTTPException(status_code=422, detail="Taxonomiya ID yaroqsiz")
        clauses.append("q.taxonomy_id=CAST(:taxonomy_id AS UUID)")
    with engine.connect() as c:
        rows = c.execute(text("""SELECT q.id::text AS id,q.owner_id::text AS owner_id,q.kind,q.section,q.prompt,q.choices,q.answer,
          q.explanation,q.image_url,q.taxonomy_id::text AS taxonomy_id,q.difficulty,q.is_active,q.created_at,q.updated_at,
          t.domain,t.skill
          FROM questions q LEFT JOIN taxonomies t ON t.id=q.taxonomy_id WHERE """ + " AND ".join(clauses) + " ORDER BY q.created_at DESC"), params).mappings().all()
    # Return only the question-bank API fields. This avoids leaking unrelated
    # legacy columns when an existing database has a wider questions table.
    return [dict(r) for r in rows]


def validate_question(payload):
    if payload.kind not in {"mcq", "spr"} or payload.section not in {"math", "reading_writing"}:
        raise HTTPException(status_code=422, detail="Savol turi yoki bo‘limi noto‘g‘ri")
    if payload.difficulty not in {"easy", "medium", "hard"}:
        raise HTTPException(status_code=422, detail="Savol qiyinchilik darajasi noto‘g‘ri")
    choices = [choice.strip() for choice in payload.choices if choice.strip()]
    if payload.kind == "mcq" and (len(choices) < 2 or len(set(choices)) != len(choices) or payload.answer.strip() not in choices):
        raise HTTPException(status_code=422, detail="MCQ savoliga takrorlanmaydigan javob variantlari va ular ichidan to‘g‘ri javob kerak")
    if payload.kind == "spr" and choices:
        raise HTTPException(status_code=422, detail="SPR savolida variantlar bo‘lmaydi")
    image_url = str(payload.image_url) if payload.image_url else None
    if image_url and not image_url.startswith("https://"):
        raise HTTPException(status_code=422, detail="Savol rasmi HTTPS manzilda bo‘lishi kerak")
    return choices


def question_fingerprint(payload, choices):
    canonical = {
        "kind": payload.kind,
        "section": payload.section,
        "prompt": " ".join(payload.prompt.split()),
        "choices": choices,
        "answer": payload.answer.strip().casefold(),
        "explanation": " ".join(payload.explanation.split()),
        "image_url": str(payload.image_url) if payload.image_url else None,
        "taxonomy_id": payload.taxonomy_id,
        "difficulty": payload.difficulty,
    }
    return hashlib.sha256(json.dumps(canonical, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def resolve_question_selection(connection, manual_ids, rules):
    ids = []
    if manual_ids:
        ids.extend(str(row["id"]) for row in question_rows(connection, manual_ids))

    for rule in rules:
        if isinstance(rule, dict):
            rule = SelectionRule(**rule)
        if rule.section not in {"math", "reading_writing"}:
            raise HTTPException(status_code=422, detail="Savol bo‘limi noto‘g‘ri")
        if rule.difficulty not in {"easy", "medium", "hard"}:
            raise HTTPException(status_code=422, detail="Savol qiyinchilik darajasi noto‘g‘ri")
        if rule.kind is not None and rule.kind not in {"mcq", "spr"}:
            raise HTTPException(status_code=422, detail="Savol turi noto‘g‘ri")

        clauses = ["q.is_active", "q.section=:section", "q.difficulty=:difficulty"]
        params = {"section": rule.section, "difficulty": rule.difficulty, "count": rule.count}
        if rule.kind:
            clauses.append("q.kind=:kind")
            params["kind"] = rule.kind
        if rule.taxonomy_id:
            try:
                params["taxonomy"] = str(uuid.UUID(rule.taxonomy_id))
            except ValueError:
                raise HTTPException(status_code=422, detail="Taksonomiya ID yaroqsiz")
            clauses.append("q.taxonomy_id=CAST(:taxonomy AS UUID)")

        rows = connection.execute(
            text("""SELECT q.id::text AS id FROM questions q
              WHERE """ + " AND ".join(clauses) +
              " ORDER BY RANDOM() LIMIT :count"),
            params,
        ).mappings().all()
        if len(rows) != rule.count:
            raise HTTPException(
                status_code=422,
                detail=f"Tanlangan shartlar uchun yetarli savol yo‘q: {rule.section}, {rule.difficulty}, {rule.count} ta kerak",
            )
        ids.extend(row["id"] for row in rows)

    unique_ids = list(dict.fromkeys(ids))
    if not unique_ids:
        raise HTTPException(status_code=422, detail="Kamida bitta savol tanlang yoki qoidalar qo‘shing")
    return unique_ids


def ensure_private_bucket():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        return False
    try:
        response=httpx.get(f"{SUPABASE_URL}/storage/v1/bucket/{quote(SUPABASE_STORAGE_BUCKET,safe='')}",headers={"Authorization":f"Bearer {SUPABASE_SERVICE_ROLE_KEY}","apikey":SUPABASE_SERVICE_ROLE_KEY},timeout=10)
        response.raise_for_status()
        if response.json().get("public") is not False:
            raise HTTPException(status_code=503,detail="Supabase Storage bucket public bo‘lmasligi kerak")
    except httpx.HTTPError:
        raise HTTPException(status_code=503,detail="Private Supabase Storage bucket topilmadi")
    return True


@router.post("/questions", status_code=201)
def create_question(payload: QuestionWrite, user=Depends(get_current_user)):
    require_roles(user, "teacher", "admin", "super_admin")
    choices = validate_question(payload)
    with engine.begin() as c:
        if payload.taxonomy_id:
            taxonomy = c.execute(text("SELECT section FROM taxonomies WHERE id=CAST(:id AS UUID)"), {"id": payload.taxonomy_id}).first()
            if not taxonomy or taxonomy[0] != payload.section: raise HTTPException(status_code=422, detail="Taxonomiya savol bo‘limiga mos emas")
        try:
            row = c.execute(text("""INSERT INTO questions(owner_id,kind,section,prompt,choices,answer,explanation,image_url,taxonomy_id,difficulty,content_hash)
              VALUES(CAST(:uid AS UUID),:kind,:section,:prompt,CAST(:choices AS JSONB),:answer,:explanation,:image,CAST(:taxonomy AS UUID),:difficulty,:fingerprint) RETURNING *"""),
              {"uid": str(user["id"]), "kind": payload.kind, "section": payload.section, "prompt": payload.prompt, "choices": json.dumps(choices), "answer": payload.answer.strip(), "explanation": payload.explanation, "image": str(payload.image_url) if payload.image_url else None, "taxonomy": payload.taxonomy_id, "difficulty": payload.difficulty, "fingerprint": question_fingerprint(payload, choices)}).mappings().first()
        except IntegrityError:
            raise HTTPException(status_code=409, detail="Bu savol savollar bankida avvaldan mavjud")
        audit(c, user, "question_created", "question", row["id"], {"kind": payload.kind, "section": payload.section})
    return public_row(row)


@router.patch("/questions/{question_id}")
def update_question(question_id: str, payload: QuestionWrite, user=Depends(get_current_user)):
    require_roles(user, "teacher", "admin", "super_admin")
    choices = validate_question(payload)
    with engine.begin() as c:
        if payload.taxonomy_id:
            taxonomy=c.execute(text("SELECT section FROM taxonomies WHERE id=CAST(:id AS UUID)"),{"id":payload.taxonomy_id}).first()
            if not taxonomy or taxonomy[0]!=payload.section:raise HTTPException(status_code=422,detail="Taxonomiya savol bo‘limiga mos emas")
        try:
            row = c.execute(text("""UPDATE questions SET kind=:kind,section=:section,prompt=:prompt,choices=CAST(:choices AS JSONB),answer=:answer,
          explanation=:explanation,image_url=:image,taxonomy_id=CAST(:taxonomy AS UUID),difficulty=:difficulty,content_hash=:fingerprint,updated_at=NOW()
          WHERE id=CAST(:id AS UUID) RETURNING *"""),
          {"kind": payload.kind, "section": payload.section, "prompt": payload.prompt, "choices": json.dumps(choices), "answer": payload.answer.strip(), "explanation": payload.explanation, "image": str(payload.image_url) if payload.image_url else None, "taxonomy": payload.taxonomy_id, "difficulty": payload.difficulty, "fingerprint": question_fingerprint(payload, choices), "id": question_id}).mappings().first()
        except IntegrityError:
            raise HTTPException(status_code=409,detail="Tahrirlangan savol shu savollar bankida mavjud")
        if not row: raise HTTPException(status_code=404, detail="Savol topilmadi yoki tahrirlashga ruxsat yo‘q")
    return public_row(row)


@router.get("/taxonomies")
def list_taxonomies(user=Depends(get_current_user)):
    with engine.connect() as c: rows = c.execute(text("SELECT * FROM taxonomies ORDER BY section,domain,skill")).mappings().all()
    return [public_row(row) for row in rows]


@router.post("/taxonomies", status_code=201)
def create_taxonomy(payload: TaxonomyWrite, user=Depends(get_current_user)):
    require_roles(user, "admin", "super_admin")
    if payload.section not in {"math", "reading_writing"}: raise HTTPException(status_code=422, detail="Bo‘lim noto‘g‘ri")
    try:
        with engine.begin() as c:
            row = c.execute(text("INSERT INTO taxonomies(section,domain,skill,created_by) VALUES (:section,:domain,:skill,CAST(:uid AS UUID)) RETURNING *"), {"section": payload.section, "domain": payload.domain.strip(), "skill": payload.skill.strip(), "uid": str(user["id"])}).mappings().first()
            audit(c, user, "taxonomy_created", "taxonomy", row["id"])
    except IntegrityError: raise HTTPException(status_code=409, detail="Bu taksonomiya allaqachon mavjud")
    return public_row(row)


@router.patch("/taxonomies/{taxonomy_id}")
def update_taxonomy(taxonomy_id:str,payload:TaxonomyWrite,user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    if payload.section not in {"math","reading_writing"}:raise HTTPException(status_code=422,detail="Bo‘lim noto‘g‘ri")
    try:
        with engine.begin() as c:
            existing=c.execute(text("SELECT section FROM taxonomies WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":taxonomy_id}).first()
            if not existing:raise HTTPException(status_code=404,detail="Taksonomiya topilmadi")
            if existing[0]!=payload.section and c.execute(text("SELECT 1 FROM questions WHERE taxonomy_id=CAST(:id AS UUID) LIMIT 1"),{"id":taxonomy_id}).first():raise HTTPException(status_code=409,detail="Savollarga ishlatilayotgan taksonomiya bo‘limini o‘zgartirib bo‘lmaydi")
            row=c.execute(text("UPDATE taxonomies SET section=:section,domain=:domain,skill=:skill WHERE id=CAST(:id AS UUID) RETURNING *"),{"section":payload.section,"domain":payload.domain.strip(),"skill":payload.skill.strip(),"id":taxonomy_id}).mappings().first()
            audit(c,user,"taxonomy_updated","taxonomy",taxonomy_id)
    except IntegrityError:raise HTTPException(status_code=409,detail="Bu taksonomiya allaqachon mavjud")
    return public_row(row)


@router.delete("/taxonomies/{taxonomy_id}")
def delete_taxonomy(taxonomy_id:str,user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.begin() as c:
        if c.execute(text("SELECT 1 FROM questions WHERE taxonomy_id=CAST(:id AS UUID) LIMIT 1"),{"id":taxonomy_id}).first():raise HTTPException(status_code=409,detail="Savollarga biriktirilgan taksonomiyani olib bo‘lmaydi")
        row=c.execute(text("DELETE FROM taxonomies WHERE id=CAST(:id AS UUID) RETURNING id"),{"id":taxonomy_id}).first()
        if not row:raise HTTPException(status_code=404,detail="Taksonomiya topilmadi")
        audit(c,user,"taxonomy_deleted","taxonomy",taxonomy_id)
    return {"status":"deleted"}


@router.get("/assignments")
def list_assignments(user=Depends(get_current_user)):
    with engine.connect() as c:
        rows = c.execute(text("""SELECT a.*,g.name AS group_name,(SELECT COUNT(*) FROM assignment_submissions s WHERE s.assignment_id=a.id) AS submission_count,
          (SELECT jsonb_build_object('raw_score',s.raw_score,'total_questions',s.total_questions,'submitted_at',s.submitted_at) FROM assignment_submissions s WHERE s.assignment_id=a.id AND s.student_id=CAST(:uid AS UUID)) AS my_submission
          FROM assignments a JOIN groups g ON g.id=a.group_id WHERE (:staff AND (:admin OR a.teacher_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=g.id AND gt.teacher_id=CAST(:uid AS UUID))))
          OR (a.status='published' AND EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=a.group_id AND gm.student_id=CAST(:uid AS UUID))) ORDER BY a.created_at DESC"""), {"staff": user["role"] in {"teacher","admin","super_admin"}, "admin": is_admin(user), "uid": str(user["id"])}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/assignments", status_code=201)
def create_assignment(payload: AssignmentWrite, user=Depends(get_current_user)):
    require_roles(user, "teacher", "admin", "super_admin")
    if payload.deadline and payload.deadline.tzinfo is None: raise HTTPException(status_code=422, detail="Muddat timezone bilan yuborilishi kerak")
    with engine.begin() as c:
        if not group_allowed(c,user,payload.group_id,write=True): raise HTTPException(status_code=404, detail="Guruh topilmadi")
        selection_rules = [rule.model_dump() for rule in payload.selection_rules]
        if payload.question_ids or selection_rules:
            resolve_question_selection(c, payload.question_ids, payload.selection_rules)
        row = c.execute(text("INSERT INTO assignments(teacher_id,group_id,title,description,question_ids,selection_rules,deadline) VALUES(CAST(:uid AS UUID),CAST(:gid AS UUID),:title,:description,CAST(:qids AS JSONB),CAST(:rules AS JSONB),:deadline) RETURNING *"),
          {"uid":str(user["id"]),"gid":payload.group_id,"title":payload.title,"description":payload.description,"qids":json.dumps(payload.question_ids),"rules":json.dumps(selection_rules),"deadline":payload.deadline}).mappings().first()
        audit(c,user,"assignment_draft_created","assignment",row["id"])
    return public_row(row)


@router.patch("/assignments/{assignment_id}")
def update_assignment(assignment_id: str, payload: AssignmentWrite, user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    if payload.deadline and payload.deadline.tzinfo is None: raise HTTPException(status_code=422,detail="Muddat timezone bilan yuborilishi kerak")
    with engine.begin() as c:
        old=c.execute(text("SELECT * FROM assignments WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":assignment_id}).mappings().first()
        if not old or (not is_admin(user) and str(old["teacher_id"])!=str(user["id"]) and not group_allowed(c,user,old["group_id"],write=True)): raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        if old["status"]!="draft": raise HTTPException(status_code=409,detail="Faqat qoralama vazifani tahrirlash mumkin")
        if not group_allowed(c,user,payload.group_id,write=True): raise HTTPException(status_code=404,detail="Guruh topilmadi")
        selection_rules = [rule.model_dump() for rule in payload.selection_rules]
        if payload.question_ids or selection_rules:
            resolve_question_selection(c, payload.question_ids, payload.selection_rules)
        row=c.execute(text("UPDATE assignments SET group_id=CAST(:gid AS UUID),title=:title,description=:description,question_ids=CAST(:qids AS JSONB),selection_rules=CAST(:rules AS JSONB),deadline=:deadline,updated_at=NOW() WHERE id=CAST(:id AS UUID) RETURNING *"),{"gid":payload.group_id,"title":payload.title,"description":payload.description,"qids":json.dumps(payload.question_ids),"rules":json.dumps(selection_rules),"deadline":payload.deadline,"id":assignment_id}).mappings().first()
    return public_row(row)


@router.post("/assignments/{assignment_id}/publish")
def publish_assignment(assignment_id: str, user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        source=c.execute(text("SELECT * FROM assignments WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":assignment_id}).mappings().first()
        if not source:raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        if not is_admin(user) and str(source["teacher_id"])!=str(user["id"]) and not group_allowed(c,user,source["group_id"],write=True):raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        if not source["question_ids"] and not source["selection_rules"]:raise HTTPException(status_code=409,detail="E’lon qilishdan oldin savol qo‘shing")
        row=c.execute(text("UPDATE assignments SET status='published',updated_at=NOW() WHERE id=CAST(:id AS UUID) AND status='draft' RETURNING *"),{"id":assignment_id}).mappings().first()
        if not row: raise HTTPException(status_code=404,detail="Qoralama vazifa topilmadi yoki ruxsat yo‘q")
        audit(c,user,"assignment_published","assignment",assignment_id)
        enqueue_group_message(c,row["group_id"],f"Yangi vazifa e’lon qilindi: {row['title']}")
    return public_row(row)


@router.post("/assignments/{assignment_id}/submit")
def submit_assignment(assignment_id: str,payload: SubmissionWrite,user=Depends(get_current_user)):
    require_roles(user,"student")
    with engine.begin() as c:
        assignment=c.execute(text("SELECT * FROM assignments WHERE id=CAST(:id AS UUID) AND status='published' FOR UPDATE"),{"id":assignment_id}).mappings().first()
        if not assignment or not group_allowed(c,user,assignment["group_id"]): raise HTTPException(status_code=404,detail="Ochiq vazifa topilmadi")
        if assignment["deadline"] and assignment["deadline"]<datetime.now(timezone.utc): raise HTTPException(status_code=410,detail="Vazifa muddati tugagan")
        set_row=c.execute(text("SELECT question_ids FROM assignment_question_sets WHERE assignment_id=CAST(:aid AS UUID) AND student_id=CAST(:uid AS UUID)"),{"aid":assignment_id,"uid":str(user["id"])}).first()
        if set_row:
            qs=question_rows(c,list(set_row[0]))
        else:
            ids=resolve_question_selection(c,assignment["question_ids"] or [],assignment["selection_rules"] or [])
            c.execute(text("INSERT INTO assignment_question_sets(assignment_id,student_id,question_ids) VALUES(CAST(:aid AS UUID),CAST(:uid AS UUID),CAST(:ids AS JSONB))"),{"aid":assignment_id,"uid":str(user["id"]),"ids":json.dumps(ids)})
            qs=question_rows(c,ids)
        math_score,rw_score=score_answers(qs,payload.answers)
        raw=math_score+rw_score
        row=c.execute(text("""INSERT INTO assignment_submissions(assignment_id,student_id,answers,raw_score,total_questions)
          VALUES(CAST(:aid AS UUID),CAST(:uid AS UUID),CAST(:answers AS JSONB),:raw,:total)
          ON CONFLICT(assignment_id,student_id) DO UPDATE SET answers=EXCLUDED.answers,raw_score=EXCLUDED.raw_score,total_questions=EXCLUDED.total_questions,submitted_at=NOW() RETURNING *"""),
          {"aid":assignment_id,"uid":str(user["id"]),"answers":json.dumps(payload.answers),"raw":raw,"total":len(qs)}).mappings().first()
    return {"id":str(row["id"]),"raw_score":raw,"total_questions":len(qs),"raw_math":math_score,"raw_reading_writing":rw_score,"submitted_at":row["submitted_at"]}


@router.get("/assignments/{assignment_id}/questions")
def assignment_questions(assignment_id: str, user=Depends(get_current_user)):
    with engine.connect() as c:
        assignment=c.execute(text("SELECT * FROM assignments WHERE id=CAST(:id AS UUID)"),{"id":assignment_id}).mappings().first()
        if not assignment:raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        if user["role"]=="student":
            if assignment["status"]!="published" or not group_allowed(c,user,assignment["group_id"]):raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        elif not is_admin(user) and str(assignment["teacher_id"])!=str(user["id"]):raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        if user["role"]=="student":
            set_row=c.execute(text("SELECT question_ids FROM assignment_question_sets WHERE assignment_id=CAST(:aid AS UUID) AND student_id=CAST(:uid AS UUID)"),{"aid":assignment_id,"uid":str(user["id"])}).first()
            if set_row:
                ids=list(set_row[0])
            else:
                ids=resolve_question_selection(c,assignment["question_ids"] or [],assignment["selection_rules"] or [])
                c.execute(text("INSERT INTO assignment_question_sets(assignment_id,student_id,question_ids) VALUES(CAST(:aid AS UUID),CAST(:uid AS UUID),CAST(:ids AS JSONB))"),{"aid":assignment_id,"uid":str(user["id"]),"ids":json.dumps(ids)})
            questions=question_rows(c,ids)
        else:
            if assignment["selection_rules"]:
                ids=resolve_question_selection(c,assignment["question_ids"] or [],assignment["selection_rules"] or [])
            else:
                ids=assignment["question_ids"]
            questions=question_rows(c,ids)
    return [student_question(q) if user["role"]=="student" else q for q in questions]


@router.get("/assignments/{assignment_id}/submissions")
def list_submissions(assignment_id: str,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.connect() as c:
        assignment=c.execute(text("SELECT * FROM assignments WHERE id=CAST(:id AS UUID)"),{"id":assignment_id}).mappings().first()
        if not assignment or (not is_admin(user) and str(assignment["teacher_id"])!=str(user["id"]) and not group_allowed(c,user,assignment["group_id"],write=True)): raise HTTPException(status_code=404,detail="Vazifa topilmadi")
        rows=c.execute(text("SELECT s.*,u.student_id,u.first_name FROM assignment_submissions s JOIN users u ON u.id=s.student_id WHERE s.assignment_id=CAST(:id AS UUID) ORDER BY s.submitted_at DESC"),{"id":assignment_id}).mappings().all()
    return [public_row(r) for r in rows]


@router.get("/mocks")
def list_mocks(user=Depends(get_current_user)):
    with engine.connect() as c:
        rows=c.execute(text("""SELECT m.*, (SELECT COUNT(*) FROM mock_attempts ma WHERE ma.mock_id=m.id) AS attempt_count,
          (SELECT COALESCE(jsonb_agg(t.group_id::text) FILTER(WHERE t.group_id IS NOT NULL),'[]'::jsonb) FROM mock_targets t WHERE t.mock_id=m.id) AS group_ids,
          (SELECT COALESCE(jsonb_agg(t.user_id::text) FILTER(WHERE t.user_id IS NOT NULL),'[]'::jsonb) FROM mock_targets t WHERE t.mock_id=m.id) AS student_ids,
          (SELECT jsonb_build_object('attempt_number',ma.attempt_number,'raw_math',ma.raw_math,'raw_reading_writing',ma.raw_reading_writing,'total_questions',ma.total_questions) FROM mock_attempts ma WHERE ma.mock_id=m.id AND ma.student_id=CAST(:uid AS UUID) ORDER BY ma.attempt_number DESC LIMIT 1) AS my_latest_attempt FROM mocks m
          WHERE (:staff AND (:admin OR m.owner_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM mock_targets mt JOIN group_teachers gt ON gt.group_id=mt.group_id WHERE mt.mock_id=m.id AND gt.teacher_id=CAST(:uid AS UUID)))) OR (m.status='open' AND (m.opens_at IS NULL OR m.opens_at<=NOW()) AND (m.deadline IS NULL OR m.deadline>=NOW()) AND EXISTS(SELECT 1 FROM mock_targets t WHERE t.mock_id=m.id AND (t.user_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=t.group_id AND gm.student_id=CAST(:uid AS UUID))))) ORDER BY m.created_at DESC"""),{"staff":user["role"] in {"teacher","admin","super_admin"},"admin":is_admin(user),"uid":str(user["id"])}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/mocks",status_code=201)
def create_mock(payload:MockWrite,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    if payload.opens_at and payload.opens_at.tzinfo is None or payload.deadline and payload.deadline.tzinfo is None: raise HTTPException(status_code=422,detail="Sana timezone bilan yuborilishi kerak")
    with engine.begin() as c:
        selection_rules=[rule.model_dump() for rule in payload.selection_rules]
        if payload.question_ids or selection_rules:
            resolved=resolve_question_selection(c,payload.question_ids,payload.selection_rules)
        else:
            raise HTTPException(status_code=422,detail="Kamida bitta savol tanlang yoki random qoidalar qo‘shing")
        qs=question_rows(c,resolved)
        for gid in set(payload.group_ids):
            if not group_allowed(c,user,gid,write=True): raise HTTPException(status_code=404,detail="Guruh topilmadi")
        row=c.execute(text("INSERT INTO mocks(owner_id,title,description,question_ids,selection_rules,opens_at,deadline) VALUES(CAST(:uid AS UUID),:title,:description,CAST(:qids AS JSONB),CAST(:rules AS JSONB),:opens,:deadline) RETURNING *"),{"uid":str(user["id"]),"title":payload.title,"description":payload.description,"qids":json.dumps(payload.question_ids),"rules":json.dumps(selection_rules),"opens":payload.opens_at,"deadline":payload.deadline}).mappings().first()
        for gid in set(payload.group_ids):c.execute(text("INSERT INTO mock_targets(mock_id,group_id) VALUES(CAST(:mid AS UUID),CAST(:gid AS UUID))"),{"mid":str(row["id"]),"gid":gid})
        for sid in set(payload.student_ids):
            valid=c.execute(text("SELECT id FROM users WHERE id=CAST(:sid AS UUID) AND role='student' AND is_active"),{"sid":sid}).first()
            if not valid:raise HTTPException(status_code=422,detail="Mock uchun tanlangan o‘quvchi topilmadi")
            c.execute(text("INSERT INTO mock_targets(mock_id,user_id) VALUES(CAST(:mid AS UUID),CAST(:sid AS UUID))"),{"mid":str(row["id"]),"sid":sid})
        audit(c,user,"mock_created","mock",row["id"],{"question_count":len(qs)})
    return public_row(row)


@router.patch("/mocks/{mock_id}")
def update_mock(mock_id:str,payload:MockWrite,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    if (payload.opens_at and payload.opens_at.tzinfo is None) or (payload.deadline and payload.deadline.tzinfo is None):raise HTTPException(status_code=422,detail="Sana timezone bilan yuborilishi kerak")
    with engine.begin() as c:
        old=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":mock_id}).mappings().first()
        if not old or(not is_admin(user) and str(old["owner_id"])!=str(user["id"])): raise HTTPException(status_code=404,detail="Mock topilmadi")
        if old["status"]!="draft": raise HTTPException(status_code=409,detail="Faqat qoralama mockni tahrirlash mumkin")
        selection_rules=[rule.model_dump() for rule in payload.selection_rules]
        if payload.question_ids or selection_rules:
            resolve_question_selection(c,payload.question_ids,payload.selection_rules)
        else:
            raise HTTPException(status_code=422,detail="Kamida bitta savol tanlang yoki random qoidalar qo‘shing")
        row=c.execute(text("UPDATE mocks SET title=:title,description=:description,question_ids=CAST(:qids AS JSONB),selection_rules=CAST(:rules AS JSONB),opens_at=:opens,deadline=:deadline,updated_at=NOW() WHERE id=CAST(:id AS UUID) RETURNING *"),{"title":payload.title,"description":payload.description,"qids":json.dumps(payload.question_ids),"rules":json.dumps(selection_rules),"opens":payload.opens_at,"deadline":payload.deadline,"id":mock_id}).mappings().first()
        c.execute(text("DELETE FROM mock_targets WHERE mock_id=CAST(:id AS UUID)"),{"id":mock_id})
        for gid in set(payload.group_ids):
            if not group_allowed(c,user,gid,write=True): raise HTTPException(status_code=404,detail="Guruh topilmadi")
            c.execute(text("INSERT INTO mock_targets(mock_id,group_id) VALUES(CAST(:mid AS UUID),CAST(:gid AS UUID))"),{"mid":mock_id,"gid":gid})
        for sid in set(payload.student_ids):
            valid=c.execute(text("SELECT id FROM users WHERE id=CAST(:sid AS UUID) AND role='student' AND is_active"),{"sid":sid}).first()
            if not valid:raise HTTPException(status_code=422,detail="Mock uchun tanlangan o‘quvchi topilmadi")
            c.execute(text("INSERT INTO mock_targets(mock_id,user_id) VALUES(CAST(:mid AS UUID),CAST(:sid AS UUID))"),{"mid":mock_id,"sid":sid})
    return public_row(row)


@router.post("/mocks/{mock_id}/open")
def open_mock(mock_id:str,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        mock=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":mock_id}).mappings().first()
        if not mock or not teacher_can_manage_mock(c,user,mock):raise HTTPException(status_code=404,detail="Mock topilmadi")
        if not mock["question_ids"] and not mock["selection_rules"]:raise HTTPException(status_code=409,detail="Mockni ochishdan oldin savollar qo‘shing")
        if not c.execute(text("SELECT 1 FROM mock_targets WHERE mock_id=CAST(:id AS UUID) LIMIT 1"),{"id":mock_id}).first():raise HTTPException(status_code=409,detail="Mockni ochishdan oldin guruh yoki o‘quvchiga biriktiring")
        row=c.execute(text("UPDATE mocks SET status='open',updated_at=NOW() WHERE id=CAST(:id AS UUID) AND status='draft' RETURNING *"),{"id":mock_id}).mappings().first()
        if not row:raise HTTPException(status_code=404,detail="Qoralama mock topilmadi")
        audit(c,user,"mock_opened","mock",mock_id)
        targets=c.execute(text("SELECT group_id,user_id FROM mock_targets WHERE mock_id=CAST(:id AS UUID)"),{"id":mock_id}).mappings().all()
        for target in targets:
            if target["group_id"]:enqueue_group_message(c,target["group_id"],f"Mock imtihon ochildi: {row['title']}")
            elif target["user_id"]:c.execute(text("INSERT INTO notification_outbox(user_id,message) SELECT id,:message FROM users WHERE id=CAST(:uid AS UUID) AND telegram_id IS NOT NULL AND is_active"),{"uid":str(target["user_id"]),"message":f"Mock imtihon ochildi: {row['title']}"})
    return public_row(row)


@router.post("/mocks/{mock_id}/close")
def close_mock(mock_id:str,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        mock=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":mock_id}).mappings().first()
        if not mock or not teacher_can_manage_mock(c,user,mock):raise HTTPException(status_code=404,detail="Ochiq mock topilmadi")
        row=c.execute(text("UPDATE mocks SET status='closed',updated_at=NOW() WHERE id=CAST(:id AS UUID) AND status='open' RETURNING *"),{"id":mock_id}).mappings().first()
        if not row:raise HTTPException(status_code=404,detail="Ochiq mock topilmadi")
    return public_row(row)


@router.post("/mocks/{mock_id}/reopen")
def reopen_mock(mock_id:str,payload:ReopenWrite,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    if payload.deadline.tzinfo is None or payload.deadline<=datetime.now(timezone.utc):raise HTTPException(status_code=422,detail="Yangi muddat kelajakdagi timezone-li vaqt bo‘lishi kerak")
    with engine.begin() as c:
        mock=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":mock_id}).mappings().first()
        if not mock or not teacher_can_manage_mock(c,user,mock):raise HTTPException(status_code=404,detail="Yopilgan mock topilmadi")
        row=c.execute(text("UPDATE mocks SET status='open',deadline=:deadline,updated_at=NOW() WHERE id=CAST(:id AS UUID) AND status='closed' RETURNING *"),{"deadline":payload.deadline,"id":mock_id}).mappings().first()
        if not row:raise HTTPException(status_code=404,detail="Yopilgan mock topilmadi")
        audit(c,user,"mock_reopened","mock",mock_id,{"deadline":payload.deadline.isoformat()})
        targets=c.execute(text("SELECT group_id,user_id FROM mock_targets WHERE mock_id=CAST(:id AS UUID)"),{"id":mock_id}).mappings().all()
        for target in targets:
            if target["group_id"]:enqueue_group_message(c,target["group_id"],f"Mock yangi muddat bilan qayta ochildi: {row['title']}")
            elif target["user_id"]:c.execute(text("INSERT INTO notification_outbox(user_id,message) SELECT id,:message FROM users WHERE id=CAST(:uid AS UUID) AND telegram_id IS NOT NULL AND is_active"),{"uid":str(target["user_id"]),"message":f"Mock yangi muddat bilan qayta ochildi: {row['title']}"})
    return public_row(row)


@router.post("/mocks/{mock_id}/attempts",status_code=201)
def submit_mock_attempt(mock_id:str,payload:SubmissionWrite,user=Depends(get_current_user)):
    require_roles(user,"student")
    with engine.begin() as c:
        mock=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID) AND status='open' AND (opens_at IS NULL OR opens_at<=NOW()) AND (deadline IS NULL OR deadline>=NOW()) FOR UPDATE"),{"id":mock_id}).mappings().first()
        if not mock:raise HTTPException(status_code=404,detail="Mock hozir ochiq emas")
        target=c.execute(text("SELECT 1 FROM mock_targets t WHERE t.mock_id=CAST(:mid AS UUID) AND (t.user_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=t.group_id AND gm.student_id=CAST(:uid AS UUID)))"),{"mid":mock_id,"uid":str(user["id"])}).first()
        if not target:raise HTTPException(status_code=403,detail="Bu mock sizga biriktirilmagan")
        set_row=c.execute(text("SELECT question_ids FROM mock_question_sets WHERE mock_id=CAST(:mid AS UUID) AND student_id=CAST(:uid AS UUID)"),{"mid":mock_id,"uid":str(user["id"])}).first()
        if set_row:
            qs=question_rows(c,list(set_row[0]),user)
        else:
            ids=resolve_question_selection(c,mock["question_ids"] or [],mock["selection_rules"] or [])
            c.execute(text("INSERT INTO mock_question_sets(mock_id,student_id,question_ids) VALUES(CAST(:mid AS UUID),CAST(:uid AS UUID),CAST(:ids AS JSONB))"),{"mid":mock_id,"uid":str(user["id"]),"ids":json.dumps(ids)})
            qs=question_rows(c,ids,user)
        math_score,rw_score=score_answers(qs,payload.answers)
        num=c.execute(text("SELECT COALESCE(MAX(attempt_number),0)+1 FROM mock_attempts WHERE mock_id=CAST(:mid AS UUID) AND student_id=CAST(:uid AS UUID)"),{"mid":mock_id,"uid":str(user["id"])}).scalar_one()
        row=c.execute(text("INSERT INTO mock_attempts(mock_id,student_id,attempt_number,answers,raw_math,raw_reading_writing,total_questions) VALUES(CAST(:mid AS UUID),CAST(:uid AS UUID),:num,CAST(:answers AS JSONB),:math,:rw,:total) RETURNING *"),{"mid":mock_id,"uid":str(user["id"]),"num":num,"answers":json.dumps(payload.answers),"math":math_score,"rw":rw_score,"total":len(qs)}).mappings().first()
    return {"id":str(row["id"]),"attempt_number":num,"raw_math":math_score,"raw_reading_writing":rw_score,"total_questions":len(qs),"score_label":"raw_score_only_not_official_sat"}


@router.get("/mocks/{mock_id}/questions")
def mock_questions(mock_id:str,user=Depends(get_current_user)):
    with engine.connect() as c:
        mock=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID)"),{"id":mock_id}).mappings().first()
        if not mock:raise HTTPException(status_code=404,detail="Mock topilmadi")
        if user["role"]=="student":
            if mock["status"]!="open" or (mock["opens_at"] and mock["opens_at"]>datetime.now(timezone.utc)) or (mock["deadline"] and mock["deadline"]<datetime.now(timezone.utc)):
                raise HTTPException(status_code=404,detail="Mock hozir ochiq emas")
            target=c.execute(text("SELECT 1 FROM mock_targets t WHERE t.mock_id=CAST(:mid AS UUID) AND (t.user_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=t.group_id AND gm.student_id=CAST(:uid AS UUID)))"),{"mid":mock_id,"uid":str(user["id"])}).first()
            if not target:raise HTTPException(status_code=403,detail="Bu mock sizga biriktirilmagan")
        elif not teacher_can_manage_mock(c,user,mock):raise HTTPException(status_code=404,detail="Mock topilmadi")
        if user["role"]=="student":
            set_row=c.execute(text("SELECT question_ids FROM mock_question_sets WHERE mock_id=CAST(:mid AS UUID) AND student_id=CAST(:uid AS UUID)"),{"mid":mock_id,"uid":str(user["id"])}).first()
            if set_row:
                ids=list(set_row[0])
            else:
                ids=resolve_question_selection(c,mock["question_ids"] or [],mock["selection_rules"] or [])
                c.execute(text("INSERT INTO mock_question_sets(mock_id,student_id,question_ids) VALUES(CAST(:mid AS UUID),CAST(:uid AS UUID),CAST(:ids AS JSONB))"),{"mid":mock_id,"uid":str(user["id"]),"ids":json.dumps(ids)})
        else:
            if mock["selection_rules"]:
                ids=resolve_question_selection(c,mock["question_ids"] or [],mock["selection_rules"] or [])
            else:
                ids=mock["question_ids"]
        questions=question_rows(c,ids)
    return [student_question(q) if user["role"]=="student" else q for q in questions]


@router.get("/mocks/{mock_id}/results")
def mock_results(mock_id:str,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.connect() as c:
        mock=c.execute(text("SELECT * FROM mocks WHERE id=CAST(:id AS UUID)"),{"id":mock_id}).mappings().first()
        if not mock or not teacher_can_manage_mock(c,user,mock):raise HTTPException(status_code=404,detail="Mock topilmadi")
        rows=c.execute(text("SELECT a.*,u.student_id,u.first_name FROM mock_attempts a JOIN users u ON u.id=a.student_id WHERE a.mock_id=CAST(:id AS UUID) ORDER BY a.submitted_at DESC"),{"id":mock_id}).mappings().all()
    return [public_row(r) for r in rows]


@router.get("/lessons")
def list_lessons(user=Depends(get_current_user)):
    with engine.connect() as c:
        rows=c.execute(text("""SELECT l.*,g.name AS group_name FROM lessons l JOIN groups g ON g.id=l.group_id WHERE
        (:staff AND (:admin OR l.teacher_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=l.group_id AND gt.teacher_id=CAST(:uid AS UUID)))) OR (l.status='published' AND EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=l.group_id AND gm.student_id=CAST(:uid AS UUID))) ORDER BY l.created_at DESC"""),{"staff":user["role"] in {"teacher","admin","super_admin"},"admin":is_admin(user),"uid":str(user["id"])}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/lessons",status_code=201)
def create_lesson(payload:LessonWrite,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        if not group_allowed(c,user,payload.group_id,write=True):raise HTTPException(status_code=404,detail="Guruh topilmadi")
        row=c.execute(text("INSERT INTO lessons(teacher_id,group_id,title,content) VALUES(CAST(:uid AS UUID),CAST(:gid AS UUID),:title,:content) RETURNING *"),{"uid":str(user["id"]),"gid":payload.group_id,"title":payload.title,"content":payload.content}).mappings().first()
    return public_row(row)


@router.post("/lessons/{lesson_id}/publish")
def publish_lesson(lesson_id:str,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        old=c.execute(text("SELECT * FROM lessons WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":lesson_id}).mappings().first()
        if not old or (not is_admin(user) and str(old["teacher_id"])!=str(user["id"]) and not group_allowed(c,user,old["group_id"],write=True)):raise HTTPException(status_code=404,detail="Dars topilmadi")
        row=c.execute(text("UPDATE lessons SET status='published',updated_at=NOW() WHERE id=CAST(:id AS UUID) RETURNING *"),{"id":lesson_id}).mappings().first()
        if not row:raise HTTPException(status_code=404,detail="Dars topilmadi")
        enqueue_group_message(c,row["group_id"],f"Yangi dars e’lon qilindi: {row['title']}")
    return public_row(row)


@router.patch("/lessons/{lesson_id}")
def update_lesson(lesson_id:str,payload:LessonWrite,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        old=c.execute(text("SELECT * FROM lessons WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":lesson_id}).mappings().first()
        if not old or(not is_admin(user) and str(old["teacher_id"])!=str(user["id"]) and not group_allowed(c,user,old["group_id"],write=True)):raise HTTPException(status_code=404,detail="Dars topilmadi")
        if old["status"]!="draft":raise HTTPException(status_code=409,detail="Faqat qoralama darsni tahrirlash mumkin")
        if not group_allowed(c,user,payload.group_id,write=True):raise HTTPException(status_code=404,detail="Guruh topilmadi")
        row=c.execute(text("UPDATE lessons SET group_id=CAST(:gid AS UUID),title=:title,content=:content,updated_at=NOW() WHERE id=CAST(:id AS UUID) RETURNING *"),{"gid":payload.group_id,"title":payload.title,"content":payload.content,"id":lesson_id}).mappings().first()
    return public_row(row)


@router.get("/posts")
def list_posts(user=Depends(get_current_user)):
    with engine.connect() as c:
        rows=c.execute(text("SELECT p.*,g.name AS group_name FROM posts p JOIN groups g ON g.id=p.group_id WHERE :admin OR EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=p.group_id AND gm.student_id=CAST(:uid AS UUID)) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=p.group_id AND gt.teacher_id=CAST(:uid AS UUID)) ORDER BY p.created_at DESC"),{"admin":is_admin(user),"uid":str(user["id"])}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/posts",status_code=201)
def create_post(payload:PostWrite,user=Depends(get_current_user)):
    require_roles(user,"teacher","admin","super_admin")
    with engine.begin() as c:
        if not group_allowed(c,user,payload.group_id,write=True):raise HTTPException(status_code=404,detail="Guruh topilmadi")
        row=c.execute(text("INSERT INTO posts(author_id,group_id,body) VALUES(CAST(:uid AS UUID),CAST(:gid AS UUID),:body) RETURNING *"),{"uid":str(user["id"]),"gid":payload.group_id,"body":payload.body}).mappings().first()
        enqueue_group_message(c,payload.group_id,f"Guruhda yangi e’lon: {payload.body[:300]}")
    return public_row(row)


def resource_target_allowed(c,user,target_type,target_id):
    if target_type=="group":return group_allowed(c,user,target_id,write=True)
    if target_type=="assignment":
        row=c.execute(text("SELECT teacher_id,group_id FROM assignments WHERE id=CAST(:id AS UUID)"),{"id":target_id}).first()
        return bool(row and (is_admin(user) or str(row[0])==str(user["id"]) or group_allowed(c,user,row[1],write=True)))
    if target_type=="lesson":
        row=c.execute(text("SELECT teacher_id,group_id FROM lessons WHERE id=CAST(:id AS UUID)"),{"id":target_id}).first()
        return bool(row and (is_admin(user) or str(row[0])==str(user["id"]) or group_allowed(c,user,row[1],write=True)))
    if target_type=="post":
        row=c.execute(text("SELECT author_id,group_id FROM posts WHERE id=CAST(:id AS UUID)"),{"id":target_id}).first()
        return bool(row and (is_admin(user) or str(row[0])==str(user["id"]) or group_allowed(c,user,row[1],write=True)))
    return False


@router.post("/resources",status_code=201)
def upload_resource(file:UploadFile=File(...),user=Depends(get_current_user)):
    if file.content_type not in ALLOWED_UPLOAD_TYPES:raise HTTPException(status_code=415,detail="Fayl turi qo‘llab-quvvatlanmaydi")
    content=file.file.read(MAX_UPLOAD_BYTES+1)
    if not content or len(content)>MAX_UPLOAD_BYTES:raise HTTPException(status_code=413,detail="Fayl bo‘sh yoki hajmi 10 MB dan oshgan")
    if file.content_type=="application/pdf" and not content.startswith(b"%PDF-"):raise HTTPException(status_code=415,detail="PDF fayli yaroqsiz")
    if file.content_type.startswith("image/") and not content.startswith((b"\x89PNG\r\n\x1a\n",b"\xff\xd8\xff",b"RIFF")):raise HTTPException(status_code=415,detail="Rasm fayli yaroqsiz")
    suffix=Path(file.filename or "file").suffix.lower()[:12]
    object_name=f"{uuid.uuid4().hex}{suffix}"
    if (SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY) and not (SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY):
        raise HTTPException(status_code=503,detail="SUPABASE_URL va SUPABASE_SERVICE_ROLE_KEY ikkalasi ham kerak")
    if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        ensure_private_bucket()
        try:
            response=httpx.post(f"{SUPABASE_URL}/storage/v1/object/{quote(SUPABASE_STORAGE_BUCKET,safe='')}/{quote(object_name,safe='')}",headers={"Authorization":f"Bearer {SUPABASE_SERVICE_ROLE_KEY}","apikey":SUPABASE_SERVICE_ROLE_KEY,"Content-Type":file.content_type,"x-upsert":"false"},content=content,timeout=30)
            response.raise_for_status()
        except httpx.HTTPError:
            raise HTTPException(status_code=502,detail="Faylni Supabase Storage’ga yuklab bo‘lmadi")
        storage_path=f"supabase:{object_name}"
    else:
        UPLOAD_DIR.mkdir(parents=True,exist_ok=True)
        target=UPLOAD_DIR/object_name
        target.write_bytes(content)
        storage_path=object_name
    with engine.begin() as c:
        row=c.execute(text("INSERT INTO resources(owner_id,filename,content_type,size_bytes,storage_path) VALUES(CAST(:uid AS UUID),:name,:type,:size,:path) RETURNING *"),{"uid":str(user["id"]),"name":Path(file.filename or "upload").name[:250],"type":file.content_type,"size":len(content),"path":storage_path}).mappings().first()
    return public_row(row)


@router.get("/resources")
def list_resources(user=Depends(get_current_user)):
    with engine.connect() as c:
        rows=c.execute(text("""SELECT DISTINCT r.* FROM resources r LEFT JOIN resource_links l ON l.resource_id=r.id
          WHERE r.owner_id=CAST(:uid AS UUID) OR :admin OR
          (l.target_type='group' AND (EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=l.target_id AND gm.student_id=CAST(:uid AS UUID)) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=l.target_id AND gt.teacher_id=CAST(:uid AS UUID)))) OR
          (l.target_type='assignment' AND EXISTS(SELECT 1 FROM assignments a WHERE a.id=l.target_id AND
             ((CAST(:role AS TEXT)='student' AND a.status='published' AND EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=a.group_id AND gm.student_id=CAST(:uid AS UUID))) OR
              (CAST(:role AS TEXT)='teacher' AND (a.teacher_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=a.group_id AND gt.teacher_id=CAST(:uid AS UUID)))))) OR
          (l.target_type='lesson' AND EXISTS(SELECT 1 FROM lessons le WHERE le.id=l.target_id AND
             ((CAST(:role AS TEXT)='student' AND le.status='published' AND EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=le.group_id AND gm.student_id=CAST(:uid AS UUID))) OR
              (CAST(:role AS TEXT)='teacher' AND (le.teacher_id=CAST(:uid AS UUID) OR EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=le.group_id AND gt.teacher_id=CAST(:uid AS UUID))))))))
          OR (l.target_type='post' AND EXISTS(SELECT 1 FROM posts p WHERE p.id=l.target_id AND
             (EXISTS(SELECT 1 FROM group_members gm WHERE gm.group_id=p.group_id AND gm.student_id=CAST(:uid AS UUID)) OR
              EXISTS(SELECT 1 FROM group_teachers gt WHERE gt.group_id=p.group_id AND gt.teacher_id=CAST(:uid AS UUID)))))
          ORDER BY r.created_at DESC"""),{"uid":str(user["id"]),"admin":is_admin(user),"role":user["role"]}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/resources/{resource_id}/link",status_code=201)
def link_resource(resource_id:str,payload:LinkResource,user=Depends(get_current_user)):
    if payload.target_type not in {"group","assignment","post","lesson"}:raise HTTPException(status_code=422,detail="Resurs joyi yaroqsiz")
    with engine.begin() as c:
        resource=c.execute(text("SELECT owner_id FROM resources WHERE id=CAST(:id AS UUID)"),{"id":resource_id}).first()
        if not resource or (not is_admin(user) and str(resource[0])!=str(user["id"])):raise HTTPException(status_code=404,detail="Resurs topilmadi")
        if not resource_target_allowed(c,user,payload.target_type,payload.target_id):raise HTTPException(status_code=404,detail="Resurs biriktiriladigan obyekt topilmadi")
        try:c.execute(text("INSERT INTO resource_links(resource_id,target_type,target_id,created_by) VALUES(CAST(:rid AS UUID),:type,CAST(:tid AS UUID),CAST(:uid AS UUID))"),{"rid":resource_id,"type":payload.target_type,"tid":payload.target_id,"uid":str(user["id"])})
        except IntegrityError:raise HTTPException(status_code=409,detail="Resurs bu obyektga avval biriktirilgan")
    return {"status":"linked"}


@router.get("/resources/{resource_id}/download")
def download_resource(resource_id:str,user=Depends(get_current_user)):
    with engine.connect() as c:
        resource=c.execute(text("SELECT * FROM resources WHERE id=CAST(:id AS UUID)"),{"id":resource_id}).mappings().first()
        if not resource:raise HTTPException(status_code=404,detail="Resurs topilmadi")
        if is_admin(user) or str(resource["owner_id"])==str(user["id"]):allowed=True
        else:
            links=c.execute(text("SELECT target_type,target_id FROM resource_links WHERE resource_id=CAST(:id AS UUID)"),{"id":resource_id}).mappings().all()
            allowed=False
            for link in links:
                tid=str(link["target_id"])
                if link["target_type"]=="group" and group_allowed(c,user,tid):allowed=True
                elif link["target_type"]=="assignment":
                    item=c.execute(text("SELECT group_id,status,teacher_id FROM assignments WHERE id=CAST(:id AS UUID)"),{"id":tid}).first()
                    if item and ((user["role"]=="student" and item[1]=="published" and group_allowed(c,user,item[0])) or (user["role"]=="teacher" and (str(item[2])==str(user["id"]) or group_allowed(c,user,item[0])))):allowed=True
                elif link["target_type"]=="lesson":
                    item=c.execute(text("SELECT group_id,status,teacher_id FROM lessons WHERE id=CAST(:id AS UUID)"),{"id":tid}).first()
                    if item and ((user["role"]=="student" and item[1]=="published" and group_allowed(c,user,item[0])) or (user["role"]=="teacher" and (str(item[2])==str(user["id"]) or group_allowed(c,user,item[0])))):allowed=True
                elif link["target_type"]=="post":
                    item=c.execute(text("SELECT group_id FROM posts WHERE id=CAST(:id AS UUID)"),{"id":tid}).first()
                    if item and group_allowed(c,user,item[0]):allowed=True
        if not allowed:raise HTTPException(status_code=403,detail="Bu resursga kirish ruxsati yo‘q")
    if resource["storage_path"].startswith("supabase:"):
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:raise HTTPException(status_code=503,detail="Supabase Storage sozlanmagan")
        ensure_private_bucket()
        object_name=resource["storage_path"].removeprefix("supabase:")
        try:
            response=httpx.post(f"{SUPABASE_URL}/storage/v1/object/sign/{quote(SUPABASE_STORAGE_BUCKET,safe='')}/{quote(object_name,safe='')}",headers={"Authorization":f"Bearer {SUPABASE_SERVICE_ROLE_KEY}","apikey":SUPABASE_SERVICE_ROLE_KEY,"Content-Type":"application/json"},json={"expiresIn":60},timeout=15)
            response.raise_for_status()
            signed=response.json()["signedURL"]
        except (httpx.HTTPError,KeyError,ValueError):
            raise HTTPException(status_code=502,detail="Himoyalangan yuklab olish havolasini tayyorlab bo‘lmadi")
        if signed.startswith("/"):signed=f"{SUPABASE_URL}/storage/v1{signed}" if not signed.startswith("/storage/v1") else f"{SUPABASE_URL}{signed}"
        return RedirectResponse(signed,status_code=302)
    path=UPLOAD_DIR/resource["storage_path"]
    if not path.is_file():raise HTTPException(status_code=404,detail="Yuklangan fayl topilmadi")
    return FileResponse(path,media_type=resource["content_type"],filename=resource["filename"],content_disposition_type="attachment")


@router.get("/users")
def admin_users(search:str="",user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    term=f"%{search.strip()}%"
    with engine.connect() as c: rows=c.execute(text("SELECT id,email,telegram_id,username,first_name,last_name,role,student_id,is_active,created_at FROM users WHERE CAST(id AS TEXT) ILIKE :term OR COALESCE(email,'') ILIKE :term OR COALESCE(telegram_id::text,'') ILIKE :term OR COALESCE(student_id,'') ILIKE :term ORDER BY created_at DESC LIMIT 100"),{"term":term}).mappings().all()
    return [public_row(r) for r in rows]


@router.get("/users/{user_id}")
def user_detail(user_id:str,user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.connect() as c:row=c.execute(text("SELECT id,email,telegram_id,username,first_name,last_name,role,student_id,is_active,created_at,updated_at FROM users WHERE id=CAST(:id AS UUID)"),{"id":user_id}).mappings().first()
    if not row:raise HTTPException(status_code=404,detail="Foydalanuvchi topilmadi")
    return public_row(row)


@router.patch("/users/{user_id}/role")
def update_user_role(user_id:str,payload:RoleUpdate,user=Depends(get_current_user)):
    if payload.role not in ROLES:raise HTTPException(status_code=422,detail="Rol noto‘g‘ri")
    require_roles(user,"admin","super_admin")
    if payload.role=="super_admin" and user["role"]!="super_admin":raise HTTPException(status_code=403,detail="Super Admin rolini faqat Super Admin bera oladi")
    with engine.begin() as c:
        target=c.execute(text("SELECT role FROM users WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":user_id}).first()
        if not target:raise HTTPException(status_code=404,detail="Foydalanuvchi topilmadi")
        if target[0]=="super_admin" and user["role"]!="super_admin":raise HTTPException(status_code=403,detail="Super Admin hisobini faqat Super Admin boshqaradi")
        if user_id==str(user["id"]) and user["role"]=="super_admin" and payload.role!="super_admin":raise HTTPException(status_code=409,detail="Yagona Super Admin o‘z rolini o‘zgartira olmaydi")
        if target[0]=="super_admin" and payload.role!="super_admin" and c.execute(text("SELECT COUNT(*) FROM users WHERE role='super_admin' AND is_active")).scalar_one()<=1:raise HTTPException(status_code=409,detail="Faol Super Adminni oxirgisi bo‘lsa almashtirib bo‘lmaydi")
        row=c.execute(text("UPDATE users SET role=:role,student_id=CASE WHEN :role='student' THEN COALESCE(student_id,'STU-' || upper(substr(replace(id::text,'-',''),1,10))) ELSE NULL END,updated_at=NOW() WHERE id=CAST(:id AS UUID) RETURNING id,role,student_id"),{"role":payload.role,"id":user_id}).mappings().first()
        if not row:raise HTTPException(status_code=404,detail="Foydalanuvchi topilmadi")
        audit(c,user,"user_role_changed","user",user_id,{"role":payload.role})
    return public_row(row)


@router.patch("/users/{user_id}/active")
def update_user_active(user_id:str,payload:ActiveUpdate,user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.begin() as c:
        target=c.execute(text("SELECT role FROM users WHERE id=CAST(:id AS UUID) FOR UPDATE"),{"id":user_id}).first()
        if not target:raise HTTPException(status_code=404,detail="Foydalanuvchi topilmadi")
        if target[0]=="super_admin" and user["role"]!="super_admin":raise HTTPException(status_code=403,detail="Super Admin hisobini faqat Super Admin boshqaradi")
        if user_id==str(user["id"]) and not payload.is_active:raise HTTPException(status_code=409,detail="O‘z hisobingizni to‘xtata olmaysiz")
        row=c.execute(text("UPDATE users SET is_active=:active,updated_at=NOW() WHERE id=CAST(:id AS UUID) RETURNING id,is_active"),{"active":payload.is_active,"id":user_id}).mappings().first()
        if not row:raise HTTPException(status_code=404,detail="Foydalanuvchi topilmadi")
        audit(c,user,"user_access_changed","user",user_id,{"is_active":payload.is_active})
        if not payload.is_active:c.execute(text("UPDATE sessions SET revoked_at=NOW() WHERE user_id=CAST(:id AS UUID) AND revoked_at IS NULL"),{"id":user_id})
    return public_row(row)


@router.get("/admin/settings")
def get_settings(user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.connect() as c: rows=c.execute(text("SELECT key,value,updated_at FROM platform_settings ORDER BY key")).mappings().all()
    return [public_row(r) for r in rows]


@router.patch("/admin/settings/{key}")
def update_setting(key:str,payload:SettingUpdate,user=Depends(get_current_user)):
    require_roles(user,"super_admin")
    if key!="registration_enabled":raise HTTPException(status_code=404,detail="Sozlama topilmadi")
    with engine.begin() as c:
        row=c.execute(text("INSERT INTO platform_settings(key,value,updated_by) VALUES(:key,CAST(:value AS JSONB),CAST(:uid AS UUID)) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=NOW() RETURNING *"),{"key":key,"value":json.dumps(payload.value),"uid":str(user["id"])}).mappings().first()
        audit(c,user,"registration_setting_changed","setting",key,{"value":payload.value})
    return public_row(row)


@router.get("/admin/audit")
def admin_audit(limit:int=Query(default=100,ge=1,le=500),user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.connect() as c:rows=c.execute(text("SELECT a.*,u.email AS actor_email,u.role AS actor_role FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT :limit"),{"limit":limit}).mappings().all()
    return [public_row(r) for r in rows]


@router.post("/admin/calibrations",status_code=202)
def create_calibration(payload:dict,user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    name=str(payload.get("name","")).strip()[:160]
    matrix=payload.get("responses")
    if not name or not isinstance(matrix,list) or len(matrix)<5:raise HTTPException(status_code=422,detail="Kalibratsiya uchun nom va kamida 5 respondent kerak")
    if any(not isinstance(row,dict) or not row for row in matrix):raise HTTPException(status_code=422,detail="Javob matritsasi yaroqsiz")
    keys=set(matrix[0])
    if len(keys)<2 or any(set(row)!=keys or any(value not in {0,1,True,False,None} for value in row.values()) for row in matrix):raise HTTPException(status_code=422,detail="Har savol javobi 0, 1 yoki null bo‘lishi kerak va ustunlar bir xil bo‘lsin")
    difficulties={}
    for key in sorted(keys):
        vals=[int(r[key]) for r in matrix if r[key] is not None]
        if len(vals)<5:raise HTTPException(status_code=422,detail=f"{key} savolida kamida 5 ta javob kerak")
        p=sum(vals)/len(vals)
        difficulties[key]=round(math.log((1-p)/p),4) if p not in {0,1} else None
    result={"method":"one_parameter_rasch_item_difficulty_moment_estimate","item_difficulty_logits":difficulties,"respondents":len(matrix),"warning":"Experimental estimate; not an official SAT score or calibrated item bank."}
    with engine.begin() as c:
        row=c.execute(text("INSERT INTO calibration_jobs(created_by,name,status,response_matrix,calibration,completed_at) VALUES(CAST(:uid AS UUID),:name,'completed',CAST(:matrix AS JSONB),CAST(:result AS JSONB),NOW()) RETURNING *"),{"uid":str(user["id"]),"name":name,"matrix":json.dumps(matrix),"result":json.dumps(result)}).mappings().first()
        audit(c,user,"irt_calibration_created","calibration",row["id"],{"respondents":len(matrix)})
    return public_row(row)


@router.get("/admin/calibrations")
def list_calibrations(user=Depends(get_current_user)):
    require_roles(user,"admin","super_admin")
    with engine.connect() as c:rows=c.execute(text("SELECT * FROM calibration_jobs ORDER BY created_at DESC")).mappings().all()
    return [public_row(r) for r in rows]
