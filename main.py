import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
import os
import logging
from collections import defaultdict, deque
from contextlib import asynccontextmanager

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

BOT_TOKEN = os.getenv("BOT_TOKEN", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
JWT_SECRET = os.getenv("JWT_SECRET", "")
INTERNAL_API_SECRET = os.getenv("INTERNAL_API_SECRET", "")
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
BOT_USERNAME = os.getenv("BOT_USERNAME", "")
SUPER_ADMIN_USER_ID = os.getenv("SUPER_ADMIN_USER_ID", "").strip()
TELEGRAM_AUTH_MAX_AGE = int(os.getenv("TELEGRAM_AUTH_MAX_AGE", "86400"))

missing = [
    name
    for name, value in (
        ("BOT_TOKEN", BOT_TOKEN),
        ("DATABASE_URL", DATABASE_URL),
        ("JWT_SECRET", JWT_SECRET),
        ("INTERNAL_API_SECRET", INTERNAL_API_SECRET),
    )
    if not value
]
if missing:
    raise RuntimeError(f"Missing environment variables: {', '.join(missing)}")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)


@asynccontextmanager
async def lifespan(app):
    init_db()
    from platform_api import init_platform_schema
    with engine.begin() as connection:
        init_platform_schema(connection)
        if SUPER_ADMIN_USER_ID:
            connection.execute(text("UPDATE users SET role='super_admin',student_id=NULL WHERE id=CAST(:id AS UUID)"), {"id": SUPER_ADMIN_USER_ID})
    yield


app = FastAPI(title="Nemis Platform API", lifespan=lifespan)

CORS_ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", FRONTEND_URL).split(",") if origin.strip()]

_auth_attempts = defaultdict(deque)


@app.middleware("http")
async def auth_rate_limit(request: Request, call_next):
    if request.url.path in {"/api/auth/telegram", "/api/auth/register", "/api/auth/login", "/api/auth/complete-account"}:
        now = time.monotonic()
        bucket = _auth_attempts[request.client.host if request.client else "unknown"]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= 12:
            return JSONResponse(status_code=429, content={"detail": "Juda ko‘p urinish. Birozdan so‘ng qayta urinib ko‘ring."})
        bucket.append(now)
    return await call_next(request)


@app.middleware("http")
async def report_unhandled_errors(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception:
        logging.exception("Unhandled request error: %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Server ichki xatosi. Xatolik server jurnaliga yozildi."})


class BrowserRegisterRequest(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class BrowserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TelegramAuthRequest(BaseModel):
    init_data: str


class CompleteAccountRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    password_confirmation: str


class LinkCompleteRequest(BaseModel):
    challenge: str = Field(min_length=30, max_length=200)
    telegram_id: int
    first_name: str | None = None
    last_name: str | None = None
    username: str | None = None


def init_db():
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    telegram_id BIGINT UNIQUE,
                    email TEXT UNIQUE,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    password_hash TEXT,
                    password_salt TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    revoked_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
        )
        connection.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique ON users (LOWER(email)) WHERE email IS NOT NULL"))
        connection.execute(text("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS token_id TEXT"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_id_unique ON sessions(token_id) WHERE token_id IS NOT NULL"))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS account_link_challenges (
                id UUID PRIMARY KEY,
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                challenge_hash TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMPTZ NOT NULL,
                consumed_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS account_security_events (
                id BIGSERIAL PRIMARY KEY,
                actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                target_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return digest, salt


def create_access_token(user_id):
    expires = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    token_id = secrets.token_urlsafe(24)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO sessions (user_id, token_id) VALUES (CAST(:user_id AS UUID), :token_id)"), {"user_id": str(user_id), "token_id": token_id})
    payload = {
        "sub": str(user_id),
        "exp": expires,
        "jti": token_id,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_user(authorization: str | None = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Avtorizatsiya talab qilinadi")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload["sub"]
    except (JWTError, KeyError):
        raise HTTPException(status_code=401, detail="Token yaroqsiz yoki muddati tugagan")

    with engine.connect() as connection:
        user = connection.execute(
            text("""SELECT u.* FROM users u JOIN sessions s ON s.user_id = u.id
                WHERE u.id = CAST(:user_id AS UUID) AND s.token_id = :token_id AND s.revoked_at IS NULL"""),
            {"user_id": user_id, "token_id": payload.get("jti")},
        ).mappings().first()
    if not user:
        raise HTTPException(status_code=401, detail="Foydalanuvchi topilmadi")
    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Hisob vaqtincha to‘xtatilgan")
    return dict(user)


def public_user(user):
    return {
        "id": str(user["id"]),
        "telegram_id": user["telegram_id"],
        "email": user["email"],
        "username": user["username"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "role": user.get("role", "student"),
        "student_id": user.get("student_id"),
    }


def lock_and_check_email(connection, email, exclude_user_id=None):
    """Serialize email claims and reject an existing identity before writing."""
    connection.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:email, 0))"),
        {"email": email},
    )
    query = "SELECT id FROM users WHERE lower(btrim(email)) = :email"
    params = {"email": email}
    if exclude_user_id is not None:
        query += " AND id <> CAST(:user_id AS UUID)"
        params["user_id"] = str(exclude_user_id)
    query += " LIMIT 1"
    return connection.execute(text(query), params).first()


def verify_telegram_init_data(init_data):
    values = parse_qs(init_data, keep_blank_values=True)
    received_hash = values.pop("hash", [None])[0]
    if not received_hash:
        raise HTTPException(status_code=400, detail="Telegram hash topilmadi")

    try:
        auth_date = int(values.get("auth_date", ["0"])[0])
    except ValueError:
        raise HTTPException(status_code=400, detail="auth_date noto‘g‘ri")
    if auth_date <= 0 or auth_date > int(time.time()) + 30 or int(time.time()) - auth_date > TELEGRAM_AUTH_MAX_AGE:
        raise HTTPException(status_code=400, detail="Telegram ma’lumotlari eskirgan")

    data_check_string = "\n".join(
        f"{key}={values[key][0]}"
        for key in sorted(values)
    )
    secret_key = hmac.new(
        b"WebAppData",
        BOT_TOKEN.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    calculated_hash = hmac.new(
        secret_key,
        data_check_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(calculated_hash, received_hash):
        raise HTTPException(status_code=401, detail="Telegram initData tekshiruvidan o‘tmadi")

    try:
        return json.loads(values["user"][0])
    except (KeyError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Telegram user ma’lumotlari topilmadi")


@app.post("/api/auth/telegram")
def telegram_auth(payload: TelegramAuthRequest):
    telegram_user = verify_telegram_init_data(payload.init_data)
    telegram_id = int(telegram_user["id"])
    first_name = telegram_user.get("first_name")
    last_name = telegram_user.get("last_name")
    username = telegram_user.get("username")

    with engine.begin() as connection:
        existing = connection.execute(text("SELECT id FROM users WHERE telegram_id=:telegram_id"), {"telegram_id": telegram_id}).first()
        if not existing:
            enabled = connection.execute(text("SELECT value FROM platform_settings WHERE key='registration_enabled'")).scalar()
            if enabled is not None and not enabled:
                raise HTTPException(status_code=403, detail="Yangi ro‘yxatdan o‘tish vaqtincha yopilgan")
        connection.execute(
            text(
                """
                INSERT INTO users (
                    telegram_id, username, first_name, last_name, student_id, updated_at
                )
                VALUES (
                    :telegram_id, :username, :first_name, :last_name, :student_id, NOW()
                )
                ON CONFLICT (telegram_id) DO UPDATE SET
                    username = EXCLUDED.username,
                    first_name = EXCLUDED.first_name,
                    last_name = EXCLUDED.last_name,
                    updated_at = NOW()
                """
            ),
            {
                "telegram_id": telegram_id,
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "student_id": f"STU-{secrets.token_hex(5).upper()}",
            },
        )
        user = connection.execute(
            text("SELECT * FROM users WHERE telegram_id = :telegram_id"),
            {"telegram_id": telegram_id},
        ).mappings().first()

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Hisob vaqtincha to‘xtatilgan")

    return {
        "access_token": create_access_token(user["id"]),
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_MINUTES * 60,
        "user": public_user(dict(user)),
        "requires_account_completion": not bool(user["email"] and user["password_hash"]),
    }


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: BrowserRegisterRequest):
    email = str(payload.email).strip().lower()
    with engine.connect() as connection:
        enabled = connection.execute(text("SELECT value FROM platform_settings WHERE key='registration_enabled'")).scalar()
    if enabled is not None and not enabled:
        raise HTTPException(status_code=403, detail="Yangi ro‘yxatdan o‘tish vaqtincha yopilgan")
    password_hash, password_salt = hash_password(payload.password)

    try:
        with engine.begin() as connection:
            if lock_and_check_email(connection, email):
                raise HTTPException(status_code=409, detail="Bu email allaqachon hisobga ulangan. Mavjud hisobga kiring.")
            result = connection.execute(
                text(
                    """
                    INSERT INTO users (
                        email, first_name, password_hash, password_salt, role, student_id, updated_at
                    )
                    VALUES (
                        :email, :name, :password_hash, :password_salt, :role, :student_id, NOW()
                    )
                    RETURNING *
                    """
                ),
                {
                    "email": email,
                    "name": payload.name,
                    "password_hash": password_hash,
                    "password_salt": password_salt,
                    "role": "student",
                    "student_id": f"STU-{secrets.token_hex(5).upper()}",
                },
            )
            user = result.mappings().first()
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Bu email band")

    return {
        "access_token": create_access_token(user["id"]),
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_MINUTES * 60,
        "user": public_user(dict(user)),
    }


@app.post("/api/auth/login")
def login(payload: BrowserLoginRequest):
    email = str(payload.email).strip().lower()
    with engine.connect() as connection:
        user = connection.execute(
            text("SELECT * FROM users WHERE email = :email"),
            {"email": email},
        ).mappings().first()

    if not user or not user["password_salt"] or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Email yoki parol noto‘g‘ri")

    expected_hash, _ = hash_password(payload.password, user["password_salt"])
    if not hmac.compare_digest(expected_hash, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email yoki parol noto‘g‘ri")

    return {
        "access_token": create_access_token(user["id"]),
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_MINUTES * 60,
        "user": public_user(dict(user)),
    }


@app.post("/api/auth/complete-account")
def complete_telegram_account(payload: CompleteAccountRequest, user=Depends(get_current_user)):
    if not user["telegram_id"]:
        raise HTTPException(status_code=403, detail="Bu amal Telegram hisobini to‘ldirish uchun")
    if user["email"] or user["password_hash"]:
        raise HTTPException(status_code=409, detail="Hisob ma’lumotlari avvaldan sozlangan")
    if payload.password != payload.password_confirmation:
        raise HTTPException(status_code=422, detail="Parollar mos kelmadi")
    email = str(payload.email).strip().lower()
    password_hash, password_salt = hash_password(payload.password)
    try:
        with engine.begin() as connection:
            if lock_and_check_email(connection, email, user["id"]):
                raise HTTPException(
                    status_code=409,
                    detail="Bu email boshqa hisobga ulangan. Mavjud hisobga kiring va Profil bo‘limidan Telegramni ulang.",
                )
            result = connection.execute(text("""UPDATE users SET email=:email, password_hash=:password_hash,
                password_salt=:password_salt, updated_at=NOW() WHERE id=CAST(:user_id AS UUID)
                AND email IS NULL AND password_hash IS NULL RETURNING *"""),
                {"email": email, "password_hash": password_hash, "password_salt": password_salt, "user_id": str(user["id"])})
            updated = result.mappings().first()
            if updated:
                connection.execute(text("INSERT INTO audit_logs(actor_id,action,target_type,target_id) VALUES (CAST(:id AS UUID),'telegram_account_completed','user',:target)"), {"id": str(user["id"]), "target": str(user["id"])})
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Bu email boshqa hisobda ishlatilgan. Avval o‘sha hisobga kiring.")
    if not updated:
        raise HTTPException(status_code=409, detail="Hisob ma’lumotlari avvaldan sozlangan")
    return {"user": public_user(dict(updated))}


@app.post("/api/auth/logout")
def logout(authorization: str = Header(...)):
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Token yaroqsiz yoki muddati tugagan")
    with engine.begin() as connection:
        connection.execute(text("UPDATE sessions SET revoked_at=NOW() WHERE token_id=:token_id AND revoked_at IS NULL"), {"token_id": payload.get("jti")})
    return {"status": "ok"}


@app.post("/api/account/telegram/link")
def create_link_challenge(user=Depends(get_current_user)):
    if user["telegram_id"]:
        raise HTTPException(status_code=409, detail="Telegram hisobi allaqachon ulangan")
    if not BOT_USERNAME:
        raise HTTPException(status_code=503, detail="Telegram bot sozlanmagan")
    challenge = secrets.token_urlsafe(32)
    digest = hashlib.sha256(challenge.encode()).hexdigest()
    challenge_id = secrets.token_hex(16)
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO account_link_challenges (id,user_id,challenge_hash,expires_at) VALUES (CAST(:id AS UUID),CAST(:user_id AS UUID),:hash,NOW()+INTERVAL '10 minutes')"),
            {"id": challenge_id, "user_id": str(user["id"]), "hash": digest})
        connection.execute(text("INSERT INTO audit_logs(actor_id,action,target_type,target_id) VALUES (CAST(:id AS UUID),'telegram_link_challenge_created','user',:target)"), {"id": str(user["id"]), "target": str(user["id"])})
    return {"url": f"https://t.me/{BOT_USERNAME}?start=link_{challenge}", "expires_in": 600}


@app.delete("/api/account/telegram/link")
def disconnect_telegram(user=Depends(get_current_user)):
    if not user["telegram_id"]:
        raise HTTPException(status_code=409, detail="Telegram hisobi ulanmagan")
    if not user["email"] or not user["password_hash"]:
        raise HTTPException(status_code=409, detail="Uzishdan oldin email va parol sozlang")
    with engine.begin() as connection:
        connection.execute(text("UPDATE users SET telegram_id=NULL, updated_at=NOW() WHERE id=CAST(:id AS UUID)"), {"id": str(user["id"])})
        connection.execute(text("INSERT INTO account_security_events(actor_user_id,target_user_id,action) VALUES (CAST(:id AS UUID),CAST(:id AS UUID),'telegram_disconnected')"), {"id": str(user["id"])})
        connection.execute(text("INSERT INTO audit_logs(actor_id,action,target_type,target_id) VALUES (CAST(:id AS UUID),'telegram_disconnected','user',:target)"), {"id": str(user["id"]), "target": str(user["id"])})
    return {"status": "disconnected"}


@app.post("/api/internal/account/link/complete")
def complete_telegram_link(payload: LinkCompleteRequest, x_internal_secret: str = Header(...)):
    if not hmac.compare_digest(x_internal_secret, INTERNAL_API_SECRET):
        raise HTTPException(status_code=401, detail="Invalid internal API secret")
    digest = hashlib.sha256(payload.challenge.encode()).hexdigest()
    try:
        with engine.begin() as connection:
            challenge = connection.execute(text("""SELECT id,user_id FROM account_link_challenges WHERE challenge_hash=:hash
                AND consumed_at IS NULL AND expires_at>NOW() FOR UPDATE"""), {"hash": digest}).mappings().first()
            if not challenge:
                raise HTTPException(status_code=410, detail="Ulanish havolasi eskirgan yoki ishlatilgan")
            linked = connection.execute(text("""UPDATE users SET telegram_id=:telegram_id, username=:username,
                first_name=:first_name,last_name=:last_name,updated_at=NOW()
                WHERE id=CAST(:user_id AS UUID) AND telegram_id IS NULL RETURNING id"""),
                {**payload.model_dump(exclude={"challenge"}), "user_id": str(challenge["user_id"])})
            if not linked.first():
                raise HTTPException(status_code=409, detail="Telegram hisobi boshqa platforma hisobiga ulangan")
            connection.execute(text("UPDATE account_link_challenges SET consumed_at=NOW() WHERE id=:id"), {"id": challenge["id"]})
            connection.execute(text("INSERT INTO account_security_events(actor_user_id,target_user_id,action,metadata) VALUES (CAST(:id AS UUID),CAST(:id AS UUID),'telegram_connected',CAST(:metadata AS JSONB))"),
                {"id": str(challenge["user_id"]), "metadata": json.dumps({"telegram_id": payload.telegram_id})})
            connection.execute(text("INSERT INTO audit_logs(actor_id,action,target_type,target_id,metadata) VALUES (CAST(:id AS UUID),'telegram_connected','user',:target,CAST(:metadata AS JSONB))"),
                {"id": str(challenge["user_id"]), "target": str(challenge["user_id"]), "metadata": json.dumps({"telegram_id": payload.telegram_id})})
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Telegram hisobi boshqa platforma hisobiga ulangan")
    return {"status": "connected"}


@app.get("/api/auth/me")
def me(user=Depends(get_current_user)):
    return {"user": public_user(user), "requires_account_completion": not bool(user["email"] and user["password_hash"])}


@app.get("/health")
def health():
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
    return {"status": "ok"}


from platform_api import router as platform_router

app.include_router(platform_router)

# Put CORS outside FastAPI's error middleware too, so unexpected 500 responses
# still reach the browser as readable JSON instead of a generic fetch failure.
app = CORSMiddleware(
    app,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
