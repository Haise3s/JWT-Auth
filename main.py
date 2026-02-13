from fastapi import FastAPI, Depends, HTTPException, status
from security import check_admin_role, create_jwt_token, get_user_from_token, verify_password, get_password_hash
from models import UserCreate, UserResponse, UserUpdate
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
    return {"status": "success", 
            "message": f"Роль пользователя {user_to_change['username']} изменена на {user_to_change['user_data']['role']}"}



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


@app.patch('/update_me')
async def update_me(update_data: UserUpdate, current_username: str = Depends(get_user_from_token)):
    user = get_user(current_username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if update_data.email and update_data.email != user['user_data']['email']:
        if update_data.email in bd_email_users:
            raise HTTPException(status_code=400, detail="Email уже занят")
        
        bd_email_users.remove(user['user_data']['email'])
        user['user_data']['email'] = update_data.email
        bd_email_users.append(update_data.email)

    if update_data.password:
        user['password'] = get_password_hash(update_data.password)

    if update_data.age is not None:
        user['user_data']['age'] = update_data.age

    if update_data.username and update_data.username != user['username']:
        if get_user(update_data.username):
            raise HTTPException(status_code=400, detail="Имя уже занято")
        user['username'] = update_data.username

    return {
        "message": "Данные успешно обновлены. Если вы меняли username, получите новый токен.", 
        "user": user['username']}


@app.delete("/delete_me")
async def delete_me(current_username: str = Depends(get_user_from_token)):
    user = get_user(current_username)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_email = user['user_data']['email']
    if user_email in bd_email_users:
        bd_email_users.remove(user_email)
    
    USERS_DATA.remove(user)
    
    return {"message": f"Пользователь {current_username} успешно удален из системы"}





if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', reload = False) 