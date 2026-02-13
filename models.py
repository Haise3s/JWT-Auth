from pydantic import BaseModel, EmailStr, Field
from db import bd_email_users

class UserBase(BaseModel):
    username: str

class UserData(BaseModel):
    email: EmailStr
    age: int | None = Field(default=None, ge=0, le=110)
    registration_date: str | None = None 
    role: str = "Пользователь"

class UserCreate(UserBase):
    password: str
    user_data: UserData

class UserResponse(UserBase):
    user_data: UserData
