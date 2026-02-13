import jwt
import datetime
from fastapi import Depends, HTTPException  
from fastapi.security import OAuth2PasswordBearer
from typing import Dict
from pwdlib import PasswordHash
from db import get_user


password_helper = PasswordHash.recommended()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")



import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

if not SECRET_KEY:
    raise ValueError("SECRET_KEY не найден в переменных окружения!")


def create_jwt_token(data: Dict):
    to_encode = data.copy() 
    expire = datetime.datetime.now() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire}) 
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM) 

def get_user_from_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен просрочен")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Неверный токен") 

def get_password_hash(password: str) -> str:
    return password_helper.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_helper.verify(plain_password, hashed_password)


def check_admin_role(current_user: str = Depends(get_user_from_token)):
    user = get_user(current_user)
    if user['user_data']["role"] != "admin":
        raise HTTPException(status_code=403, detail="Только для администраторов!")
    return user