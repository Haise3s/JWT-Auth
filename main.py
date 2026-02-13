from fastapi import FastAPI, Depends, HTTPException, status
from security import check_admin_role, create_jwt_token, get_user_from_token, verify_password, get_password_hash
from models import UserCreate, UserResponse
from typing import List
from fastapi.security import OAuth2PasswordRequestForm
from db import get_user, USERS_DATA, bd_email_users
from datetime import datetime
app = FastAPI()


@app.post("/register")
async def register(user_in: UserCreate):
    if get_user(user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким именем уже существует"
        )
    if user_in.user_data.email in bd_email_users:
                raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    hashed_pass = get_password_hash(user_in.password)
    date_reg = datetime.now().strftime("%d/%m/%Y, %H:%M:%S")
    new_user = {
        "username": user_in.username,
        "password": hashed_pass,
        "user_data":{'email':user_in.user_data.email,
                     'age':user_in.user_data.age,
                     'registration_date':date_reg,
                     'role':'Пользователь' }

    }
    USERS_DATA.append(new_user)
    bd_email_users.append(user_in.user_data.email)
    return {"message": "Успешная регистрация"}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()): 
    user = get_user(form_data.username)
    if user:
        if verify_password(form_data.password, user.get('password')):
            token = create_jwt_token({"sub": form_data.username, "role": user['user_data']["role"]})
            return {
                "access_token": token, 
                "token_type": "bearer"
            }
            
    raise HTTPException(status_code=401, detail="Invalid credential")



@app.patch("/set_role")
async def set_role(target_username:str ,admin_user: dict = Depends(check_admin_role)):
    user_to_change = get_user(target_username)
    if not user_to_change:
        raise HTTPException(status_code=404, detail="Пользователь для смены роли не найден")
    user_to_change['user_data']['role'] = 'admin'
    return {"status": "success", "message": f"Роль пользователя {user_to_change['username']} изменена на {user_to_change['user_data']['role']}"}



@app.get("/about_me", response_model=UserResponse) 
async def about_me(current_user: str = Depends(get_user_from_token)):
    user_dict = get_user(current_user) 
    if user_dict:
        return {'username':user_dict.get('username'),
                'user_data':user_dict.get('user_data')}

    raise HTTPException(status_code=404, detail="User not found")


@app.get('/all_users_info', response_model=List[UserResponse])
async def all_users_info(admin: dict = Depends(check_admin_role)):
     return USERS_DATA



if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', reload = False) 