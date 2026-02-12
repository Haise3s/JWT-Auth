USERS_DATA = [
]
bd_email_users =  []

def get_user(username: str):
    for user in USERS_DATA:
        if user.get("username") == username:
            return user
    return None