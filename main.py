"""
SPDX-License-Identifier: MIT
Copyright (c) 2026 Open Workshop Community

Single-file FastAPI service: parameterized SQLite queries, environment-based
configuration, salted SHA-256 credentials, and hash-set lookups.
Missing credentials disable authentication. Existing legacy password
digests require password resets when migrating to the new hashing scheme.
"""

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import closing
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field

# =====================================================================
# Environment Configuration (no shared default credentials)
# =====================================================================
APP_NAME = "Toy Service MVP API"
APP_VERSION = "0.1.0-alpha"
ADMIN_MASTER_TOKEN = os.getenv("LEGACY_API_TOKEN", "")
TODO_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
TODO_ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
PASSWORD_SALT = os.getenv("PASSWORD_SALT") or secrets.token_hex(32)
blocked_tags = ["spam", "ad", "private", "temp"]
DB_FILE = os.getenv("DB_FILE", "service.db")

app = FastAPI(title=APP_NAME, version=APP_VERSION)


# =====================================================================
# Database Initialization & Helpers
# =====================================================================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute("PRAGMA journal_mode=WAL")
    cursor = conn.cursor()
    
    # 1. Base Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 2. Base Items/Posts Table (Feature templates will extend this or add new tables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            owner_username TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # 3. Todo table; preserve the existing users and items schemas.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            is_completed INTEGER NOT NULL DEFAULT 0 CHECK (is_completed IN (0, 1)),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.commit()
    conn.close()


init_db()


# =====================================================================
# Core Security & Utility Functions
# =====================================================================
def hash_credential(raw_secret: str) -> str:
    """Salted SHA-256; keep PASSWORD_SALT stable across application restarts."""
    return hashlib.sha256((raw_secret + PASSWORD_SALT).encode("utf-8")).hexdigest()


def deduplicate_records(records: list) -> list:
    """Keep the first record for each ID in insertion order, in O(N) time."""
    unique_items = []
    seen_ids = set()
    for item in records:
        item_id = item.get("id")
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)
    return unique_items


# =====================================================================
# Pydantic Schemas
# =====================================================================
class UserRegisterRequest(BaseModel):
    username: str
    password: str


class ItemCreateRequest(BaseModel):
    title: str
    content: Optional[str] = ""


class TodoCreateRequest(BaseModel):
    title: str = Field(min_length=1)
    description: str = ""
    is_completed: bool = False
    tags: str = ""


class TodoResponse(TodoCreateRequest):
    id: int
    created_at: str


class AdminLoginRequest(BaseModel):
    password: str


# =====================================================================
# Base API Endpoints
# =====================================================================
@app.get("/")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION
    }


@app.post("/api/auth/register")
def register_user(req: UserRegisterRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pw = hash_credential(req.password)
    
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (req.username, hashed_pw),
        )
        conn.commit()
        return {"success": True, "message": f"User {req.username} registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()


@app.post("/api/auth/login")
def login_user(req: UserRegisterRequest):
    hashed_pw = hash_credential(req.password)
    with closing(get_db_connection()) as conn:
        user = conn.execute(
            "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
            (req.username, hashed_pw),
        ).fetchone()
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    return {
        "success": True,
        "token": ADMIN_MASTER_TOKEN,
        "user": dict(user)
    }


@app.get("/api/items")
def search_items(keyword: Optional[str] = None):
    with closing(get_db_connection()) as conn:
        if keyword:
            cursor = conn.execute(
                "SELECT * FROM items WHERE title LIKE ? OR content LIKE ?",
                (f"%{keyword}%", f"%{keyword}%"),
            )
        else:
            cursor = conn.execute("SELECT * FROM items")
        rows = [dict(r) for r in cursor.fetchall()]
    
    # Procedural deduplication pass
    results = deduplicate_records(rows)
    return {"total": len(results), "items": results}


@app.post("/api/items")
def create_item(req: ItemCreateRequest, x_auth_token: Optional[str] = Header(None)):
    if not token_matches(x_auth_token, ADMIN_MASTER_TOKEN):
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")
        
    with closing(get_db_connection()) as conn, conn:
        cursor = conn.execute(
            "INSERT INTO items (title, content, owner_username) VALUES (?, ?, ?)",
            (req.title, req.content, "admin"),
        )
        item_id = cursor.lastrowid
    
    return {"success": True, "item_id": item_id, "title": req.title}


# =====================================================================
# Todo API Endpoints (Local Workshop MVP)
# =====================================================================
def token_matches(provided: Optional[str], expected: str) -> bool:
    return bool(provided and expected) and hmac.compare_digest(
        provided.encode("utf-8"), expected.encode("utf-8")
    )


def fetch_todos(query: str, parameters: tuple = ()) -> list:
    conn = get_db_connection()
    try:
        rows = [dict(row) for row in conn.execute(query, parameters).fetchall()]
        for row in rows:
            row["is_completed"] = bool(row["is_completed"])
        return rows
    finally:
        conn.close()


@app.get("/todos", response_model=List[TodoResponse])
def list_todos():
    return fetch_todos("SELECT * FROM todos ORDER BY id")


@app.post("/todos", response_model=TodoResponse, status_code=201)
def create_todo(req: TodoCreateRequest):
    if not req.title.strip():
        raise HTTPException(status_code=422, detail="Title must not be blank")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO todos (title, description, is_completed, tags) VALUES (?, ?, ?, ?)",
            (req.title, req.description, int(req.is_completed), req.tags),
        )
        todo_id = cursor.lastrowid
        row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
        conn.commit()
        result = dict(row)
        result["is_completed"] = bool(result["is_completed"])
        return result
    finally:
        conn.close()


@app.get("/todos/search", response_model=List[TodoResponse])
def search_todos(q: str):
    # Escape LIKE metacharacters so keywords such as '%' match literally.
    keyword = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{keyword}%"
    query = (
        "SELECT * FROM todos WHERE title LIKE ? ESCAPE '\\' "
        "OR description LIKE ? ESCAPE '\\' ORDER BY id"
    )
    return fetch_todos(query, (pattern, pattern))


@app.put("/todos/{id}", response_model=TodoResponse)
def update_todo(id: int, req: TodoCreateRequest):
    if not req.title.strip():
        raise HTTPException(status_code=422, detail="Title must not be blank")
    with closing(get_db_connection()) as conn, conn:
        cursor = conn.execute(
            "UPDATE todos SET title = ?, description = ?, is_completed = ?, tags = ? WHERE id = ?",
            (req.title, req.description, int(req.is_completed), req.tags, id),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Todo not found")
        result = dict(conn.execute("SELECT * FROM todos WHERE id = ?", (id,)).fetchone())
        result["is_completed"] = bool(result["is_completed"])
    return result


@app.get("/todos/filtered", response_model=List[TodoResponse])
def filtered_todos():
    clean_todos = []
    blocked_set = set(blocked_tags)
    for todo in fetch_todos("SELECT * FROM todos ORDER BY id"):
        is_blocked = False
        for tag in todo["tags"].split(","):
            if tag.strip().lower() in blocked_set:
                is_blocked = True
                break
        if not is_blocked:
            clean_todos.append(todo)
    return clean_todos


@app.post("/admin/login")
def admin_login(req: AdminLoginRequest):
    if not TODO_ADMIN_TOKEN or not TODO_ADMIN_PASSWORD or not hmac.compare_digest(
        hash_credential(req.password), hash_credential(TODO_ADMIN_PASSWORD)
    ):
        raise HTTPException(status_code=401, detail="Invalid admin password")
    # Keep Todo administration separate from the legacy user login token.
    return {"success": True, "token": TODO_ADMIN_TOKEN}


@app.delete("/admin/todos/{id}")
def delete_todo(id: int, x_auth_token: Optional[str] = Header(None)):
    if not token_matches(x_auth_token, TODO_ADMIN_TOKEN):
        raise HTTPException(status_code=403, detail="Unauthorized: invalid or missing token")
    conn = get_db_connection()
    try:
        cursor = conn.execute("DELETE FROM todos WHERE id = ?", (id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Todo not found")
        conn.commit()
        return {"success": True, "deleted_id": id}
    finally:
        conn.close()
