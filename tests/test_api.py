import hashlib
import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api(tmp_path, monkeypatch):
    source = Path(__file__).resolve().parents[1] / "main.py"
    monkeypatch.chdir(tmp_path)
    for name, value in {
        "ADMIN_TOKEN": "test-admin-token",
        "LEGACY_API_TOKEN": "test-legacy-token",
        "ADMIN_PASSWORD": "test-admin-password",
        "PASSWORD_SALT": "test-salt",
    }.items():
        monkeypatch.setenv(name, value)
    spec = importlib.util.spec_from_file_location("todo_test_app", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app) as client:
        yield client, module


def test_todos_search_filter_and_persistence(api):
    client, module = api
    assert client.get("/todos").json() == []
    payload = {"title": "Alice's task", "description": "100%_done\\today", "tags": "adapter,work"}
    created = client.post("/todos", json=payload)
    assert created.status_code == 201
    todo = created.json()
    assert todo == {**payload, "id": 1, "is_completed": False, "created_at": todo["created_at"]}
    for keyword in ["Alice's", "100%_", "\\today"]:
        assert client.get("/todos/search", params={"q": keyword}).json() == [todo]
    assert client.get("/todos/search", params={"q": "' OR 1=1 --"}).json() == []
    assert client.get("/todos/search").status_code == 422
    for tag in module.blocked_tags:
        response = client.post("/todos", json={"title": tag, "tags": f"work, {tag.upper()} "})
        assert response.status_code == 201
    assert client.get("/todos/filtered").json() == [todo]
    module.init_db()
    assert len(client.get("/todos").json()) == 5
    with module.get_db_connection() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert client.post("/todos", json={"title": " "}).status_code == 422
    assert client.post("/todos", json={}).status_code == 422


def test_admin_authentication_and_delete(api):
    client, module = api
    todo_id = client.post("/todos", json={"title": "Delete me", "is_completed": True}).json()["id"]
    assert client.post("/admin/login", json={"password": "wrong"}).status_code == 401
    login = client.post("/admin/login", json={"password": "test-admin-password"})
    assert login.json() == {"success": True, "token": "test-admin-token"}
    for token in [None, "wrong", module.ADMIN_MASTER_TOKEN]:
        headers = {"X-Auth-Token": token} if token else {}
        assert client.delete(f"/admin/todos/{todo_id}", headers=headers).status_code == 403
    headers = {"X-Auth-Token": login.json()["token"]}
    assert client.delete(f"/admin/todos/{todo_id}", headers=headers).json() == {"success": True, "deleted_id": todo_id}
    assert client.delete(f"/admin/todos/{todo_id}", headers=headers).status_code == 404
    assert client.delete("/admin/todos/invalid", headers=headers).status_code == 422
    assert not module.token_matches("", "")


def test_legacy_auth_sql_injection_and_items(api):
    client, module = api
    credentials = {"username": "O'Brien' OR 1=1 --", "password": "secret"}
    assert client.post("/api/auth/register", json=credentials).status_code == 200
    assert client.post("/api/auth/register", json=credentials).status_code == 400
    login = client.post("/api/auth/login", json=credentials)
    assert login.status_code == 200
    assert login.json()["user"]["username"] == credentials["username"]
    assert login.json()["token"] == "test-legacy-token"
    for username, password in [(credentials["username"], "wrong"), ("' OR 1=1 --", "secret")]:
        assert client.post("/api/auth/login", json={"username": username, "password": password}).status_code == 401
    with module.get_db_connection() as conn:
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]
    assert stored == hashlib.sha256(b"secrettest-salt").hexdigest()
    payload = {"title": "x'); DROP TABLE items; --", "content": "O'Brien"}
    assert client.post("/api/items", json=payload).status_code == 403
    response = client.post("/api/items", json=payload, headers={"X-Auth-Token": "test-legacy-token"})
    assert response.status_code == 200
    assert client.get("/api/items").json()["total"] == 1
    assert client.get("/api/items", params={"keyword": "O'Brien"}).json()["total"] == 1
    assert client.get("/api/items", params={"keyword": "' OR 1=1 --"}).json()["total"] == 0
    assert client.get("/").json()["status"] == "healthy"
    assert client.get("/docs").status_code == 200


def test_deduplication_order_and_scale(api):
    _, module = api
    records = [{"id": i, "value": "first"} for i in range(10000)]
    duplicates = [{"id": i, "value": "second"} for i in range(10000)]
    assert module.deduplicate_records(records + duplicates) == records
    assert module.deduplicate_records([]) == []


def test_update_and_invalid_titles(api):
    client, _ = api
    created = client.post("/todos", json={"title": "Original"}).json()
    payload = {"title": "Updated", "description": "done", "is_completed": True, "tags": "work"}
    updated = client.put(f"/todos/{created['id']}", json=payload)
    assert updated.status_code == 200
    assert updated.json() == {**created, **payload}
    assert client.get("/todos").json() == [updated.json()]
    assert client.put("/todos/999", json=payload).status_code == 404
    for title in ["", " ", "\t\n"]:
        assert client.post("/todos", json={"title": title}).status_code == 422
        assert client.put(f"/todos/{created['id']}", json={"title": title}).status_code == 422


def test_missing_credentials_disable_admin(api, monkeypatch):
    client, module = api
    monkeypatch.setattr(module, "TODO_ADMIN_PASSWORD", "")
    monkeypatch.setattr(module, "TODO_ADMIN_TOKEN", "")
    assert client.post("/admin/login", json={"password": ""}).status_code == 401
    assert client.post("/admin/login", json={"password": "admin1234"}).status_code == 401
    assert client.delete("/admin/todos/1", headers={"X-Auth-Token": "fallback_dev_token"}).status_code == 403
    monkeypatch.setattr(module, "TODO_ADMIN_PASSWORD", "test-admin-password")
    assert client.post("/admin/login", json={"password": "test-admin-password"}).status_code == 401
