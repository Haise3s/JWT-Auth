from pwdlib import PasswordHash
password_helper = PasswordHash.recommended()

USERS_DATA = [
    {
        "username": "admin",
        "password": password_helper.hash("admin"),
        "user_data": {
            "email": "admin@example.com",
            "age": 30,
            "registration_date": "13/02/2026, 11:00:00",
            "role": "admin",
            "is_active": True
        }
    }
]

bd_email_users =  ["admin@example.com"]

def get_user(username: str):
    for user in USERS_DATA:
        if user.get("username") == username:
            return user
    return None