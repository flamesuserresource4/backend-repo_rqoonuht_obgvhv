"""
Database Schemas for VCET AI Chat Application

Each Pydantic model corresponds to a MongoDB collection.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List
from datetime import datetime

class Users(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email")
    password: str = Field(..., description="Hashed password")
    is_verified: bool = Field(False)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None

class Conversations(BaseModel):
    user_id: str = Field(..., description="Owner user ObjectId as string")
    title: str = Field("New Conversation", max_length=100)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    message_count: int = 0

class Messages(BaseModel):
    conversation_id: str = Field(..., description="Conversation ObjectId as string")
    user_id: Optional[str] = Field(None, description="User ObjectId for user messages")
    role: Literal['user','assistant']
    content: str
    created_at: Optional[datetime] = None

class Shares(BaseModel):
    share_id: str
    conversation_id: str
    user_id: str
    created_at: Optional[datetime] = None
    view_count: int = 0

class Liked_messages(BaseModel):
    user_id: str
    message_id: str
    conversation_id: str
    liked_at: Optional[datetime] = None

class Disliked_messages(BaseModel):
    user_id: str
    message_id: str
    conversation_id: str
    reason: str
    feedback_text: Optional[str] = None
    reported_at: Optional[datetime] = None

class Otp_codes(BaseModel):
    email: EmailStr
    otp: str = Field(..., description="Hashed OTP")
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
