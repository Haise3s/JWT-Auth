from fastapi.testclient import TestClient
from main import app  
import pytest
from security import get_password_hash
from db import USERS_DATA, bd_email_users

client = TestClient(app)

def test_root_registration():
    """Проверяем, что регистрация проходит успешно"""
    response = client.post("/register", json={
        "username": "test_user_1",
        "password": "strong_password",
        "user_data": {
            "email": "test1@example.com",
            "age": 25
        }
    })
    assert response.status_code == 200
    assert response.json()["message"] == "Успешная регистрация"

def test_duplicate_registration_logic():
    user_data = {
        "username": "double_user",
        "password": "123",
        "user_data": {"email": "double@test.com", "age": 20}
    }
    
    res1 = client.post("/register", json=user_data)
    assert res1.status_code == 200
    
    res2 = client.post("/register", json=user_data)
    assert res2.status_code == 400 
    assert "именем уже существует" in res2.json()["detail"]

def test_login_wrong_password():
    """Проверяем, что с неверным паролем войти нельзя"""
    client.post("/register", json={
        "username": "login_tester",
        "password": "correct_password",
        "user_data": {"email": "tester@test.com", "age": 20}
    })
    
    response = client.post("/login", data={
        "username": "login_tester", 
        "password": "WRONG_password"
    })
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credential"

def test_login_success_and_get_token():
    """Проверяем успешный вход и получение токена"""
    client.post("/register", json={
        "username": "token_user",
        "password": "password123",
        "user_data": {"email": "token@test.com", "age": 20}
    })
    
    response = client.post("/login", data={
        "username": "token_user", 
        "password": "password123"
    })
    
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_update_me_success():
    """Проверяем успешное обновление данных пользователя"""
    client.post("/register", json={
        "username": "update_user",
        "password": "old_password",
        "user_data": {"email": "old@test.com", "age": 20}
    })
    
    login_res = client.post("/login", data={"username": "update_user", "password": "old_password"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    update_payload = {
        "email": "new@test.com",
        "age": 30
    }
    response = client.patch("/update_me", json=update_payload, headers=headers)
    
    assert response.status_code == 200
    assert response.json()["message"] == "Данные успешно обновлены. Если вы меняли username, получите новый токен."
    
    me_res = client.get("/about_me", headers=headers)
    assert me_res.json()["user_data"]["email"] == "new@test.com"
    assert me_res.json()["user_data"]["age"] == 30

def test_update_me_duplicate_email():
    """Проверяем, что нельзя сменить email на уже занятый"""
    client.post("/register", json={
        "username": "user1", "password": "123", "user_data": {"email": "user1@test.com", "age": 20}
    })
    client.post("/register", json={
        "username": "user2", "password": "123", "user_data": {"email": "user2@test.com", "age": 20}
    })
    
    login_res = client.post("/login", data={"username": "user1", "password": "123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.patch("/update_me", json={"email": "user2@test.com"}, headers=headers)
    
    assert response.status_code == 400
    assert "Email уже занят" in response.json()["detail"]



def test_admin_access_all_users():
    """Проверяем, что админ видит список всех пользователей"""
    USERS_DATA.clear()
    bd_email_users.clear()
    admin_data = {
        "username": "boss",
        "password": get_password_hash("admin_pass"),
        "user_data": {"email": "admin@test.com", "age": 40, "role": "admin", "is_active": True}
    }
    USERS_DATA.append(admin_data)
    bd_email_users.append(admin_data["user_data"]["email"])
    
    login_res = client.post("/login", data={"username": "boss", "password": "admin_pass"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/all_users_info", headers=headers)
    
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert response.json()[0]["username"] == "boss"

def test_user_cannot_access_admin_endpoint():
    """Проверяем, что обычному пользователю закрыт доступ к списку всех"""
    client.post("/register", json={
        "username": "simple_guy", "password": "123", "user_data": {"email": "guy@test.com", "age": 18}
    })
    
    login_res = client.post("/login", data={"username": "simple_guy", "password": "123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    response = client.get("/all_users_info", headers=headers)
    
    assert response.status_code == 403
    assert response.json()["detail"] == "Только для администраторов!"


def test_admin_ban_user_logic():
    """Проверяем: Админ банит -> Юзер получает 403"""
    admin_pass = "admin123"
    USERS_DATA.append({
        "username": "admin", 
        "password": get_password_hash(admin_pass),
        "user_data": {"email": "admin@t.com", "age": 30, "role": "admin", "is_active": True}
    })
    
    client.post("/register", json={
        "username": "victim", "password": "123", "user_data": {"email": "v@t.com", "age": 20}
    })
    
    admin_token = client.post("/login", data={"username": "admin", "password": admin_pass}).json()["access_token"]
    user_token = client.post("/login", data={"username": "victim", "password": "123"}).json()["access_token"]
    
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    user_headers = {"Authorization": f"Bearer {user_token}"}

    assert client.get("/about_me", headers=user_headers).status_code == 200
    
    ban_res = client.patch("/admin/ban_user/victim", headers=admin_headers)
    assert ban_res.status_code == 200
    
    forbidden_res = client.get("/about_me", headers=user_headers)
    assert forbidden_res.status_code == 403
    assert "заблокирован" in forbidden_res.json()["detail"]

def test_admin_unban_user_logic():
    """Проверяем: Юзер в бане -> Админ разбанивает -> Юзер снова в деле"""
    USERS_DATA.append({
        "username": "prisoner", 
        "password": get_password_hash("123"),
        "user_data": {"email": "p@t.com", "age": 20, "role": "Пользователь", "is_active": False}
    })
    
    admin_token = client.post("/login", data={"username": "admin", "password": "admin123"}).json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    unban_res = client.patch("/admin/unban_user/prisoner", headers=admin_headers)
    assert unban_res.status_code == 200
    
    user = next(u for u in USERS_DATA if u["username"] == "prisoner")
    assert user["user_data"]["is_active"] is True


def test_delete_me_soft_logic():
    """Проверяем: Юзер удаляет себя -> Статус становится False, Email свободен"""
    client.post("/register", json={
        "username": "suicide_user", "password": "123", 
        "user_data": {"email": "bye@test.com", "age": 20}
    })
    token = client.post("/login", data={"username": "suicide_user", "password": "123"}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.delete("/delete_me", headers=headers)
    assert response.status_code == 200
    
    user = next(u for u in USERS_DATA if u["username"] == "suicide_user")
    assert user["user_data"]["is_active"] is False
    
    assert "bye@test.com" not in bd_email_users

def test_admin_delete_user_logic():
    """Проверяем: Админ удаляет юзера -> Юзер деактивирован"""
    admin_pass = "admin123"
    USERS_DATA.append({
        "username": "admin", "password": get_password_hash(admin_pass),
        "user_data": {"email": "admin@t.com", "age": 30, "role": "admin", "is_active": True}
    })
    client.post("/register", json={
        "username": "target", "password": "123", "user_data": {"email": "t@t.com", "age": 20}
    })
    
    token = client.post("/login", data={"username": "admin", "password": admin_pass}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.delete("/admin/delete_user/target", headers=headers)
    assert response.status_code == 200
    
    user = next(u for u in USERS_DATA if u["username"] == "target")
    assert user["user_data"]["is_active"] is False
    assert "t@t.com" not in bd_email_users
