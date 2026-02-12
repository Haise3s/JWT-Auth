from fastapi import FastAPI, Depends, HTTPException, status
from security import create_jwt_token, get_user_from_token, verify_password, get_password_hash
from models import User, UserBase
from fastapi.security import OAuth2PasswordRequestForm
from db import get_user, USERS_DATA

app = FastAPI()


@app.post("/register")
async def register(user_in: User):
    if get_user(user_in.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким именем уже существует"
        )
    
    hashed_pass = get_password_hash(user_in.password)
    
    new_user = {
        "username": user_in.username,
        "password": hashed_pass 
    }
    USERS_DATA.append(new_user)
    
    return {"message": "Успешная регистрация"}

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()): 
    user = get_user(form_data.username)
    if user:
        if verify_password(form_data.password, user.get('password')):
            token = create_jwt_token({"sub": form_data.username})
            return {
                "access_token": token, 
                "token_type": "bearer"
            }
            
    raise HTTPException(status_code=401, detail="Invalid credential")

@app.get("/about_me", response_model=UserBase)
async def about_me(current_user: str = Depends(get_user_from_token)):
    user_dict = get_user(current_user) 
    if user_dict:
        return user_dict

    raise HTTPException(status_code=404, detail="User not found")



if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', reload = False)