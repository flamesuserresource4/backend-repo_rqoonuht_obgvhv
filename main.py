import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents

# Security configs
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-key")
JWT_ALG = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------- Helpers ----------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_jwt(payload: dict, expires_minutes: int = 60 * 24) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode = {**payload, "exp": exp}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def decode_jwt(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid auth scheme")
        payload = decode_jwt(token)
        user_id = payload.get("user_id")
        email = payload.get("email")
        if not user_id or not email:
            raise ValueError("Invalid token payload")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ---------------------- Models ----------------------
class SignupBody(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class VerifyOtpBody(BaseModel):
    email: EmailStr
    otp: str


class ResendOtpBody(BaseModel):
    email: EmailStr


# ---------------------- Routes ----------------------
@app.get("/")
def read_root():
    return {"message": "VCET AI Backend is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


# ---------------------- Auth Endpoints ----------------------
@app.post("/api/auth/signup")
def signup(body: SignupBody):
    # Check if user exists
    existing = db["users"].find_one({"email": body.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = hash_password(body.password)
    user_doc = {
        "name": body.name,
        "email": body.email,
        "password": hashed,
        "is_verified": False,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc)
    }
    db["users"].insert_one(user_doc)

    # Create OTP entry (store hashed)
    raw_otp = "123456"  # In production, generate random and send via email
    db["otp_codes"].insert_one({
        "email": body.email,
        "otp": hash_password(raw_otp),
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
    })

    return {"success": True, "message": "OTP sent to email", "email": body.email}


@app.post("/api/auth/login")
def login(body: LoginBody):
    user = db["users"].find_one({"email": body.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(body.password, user.get("password", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not user.get("is_verified"):
        # resend OTP placeholder
        raw_otp = "123456"
        db["otp_codes"].insert_one({
            "email": body.email,
            "otp": hash_password(raw_otp),
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
        })
        return {"success": True, "verified": False, "message": "OTP sent to email"}

    token = create_jwt({"user_id": str(user["_id"]), "email": user["email"]})
    user_public = {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}
    return {"success": True, "verified": True, "token": token, "user": user_public}


@app.post("/api/auth/verify-otp")
def verify_otp(body: VerifyOtpBody):
    record = db["otp_codes"].find_one({"email": body.email}, sort=[("created_at", -1)])
    if not record:
        raise HTTPException(status_code=400, detail="OTP not found")

    if record.get("expires_at") and record["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="OTP expired")

    if not verify_password(body.otp, record.get("otp", "")):
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Mark user verified
    db["users"].update_one({"email": body.email}, {"$set": {"is_verified": True, "updated_at": datetime.now(timezone.utc)}})
    user = db["users"].find_one({"email": body.email})
    token = create_jwt({"user_id": str(user["_id"]), "email": user["email"]})
    user_public = {"id": str(user["_id"]), "name": user["name"], "email": user["email"]}
    return {"success": True, "token": token, "user": user_public}


@app.post("/api/auth/resend-otp")
def resend_otp(body: ResendOtpBody):
    user = db["users"].find_one({"email": body.email})
    if not user:
        raise HTTPException(status_code=400, detail="Email not registered")

    raw_otp = "123456"
    db["otp_codes"].insert_one({
        "email": body.email,
        "otp": hash_password(raw_otp),
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5)
    })
    return {"success": True, "message": "OTP sent"}


# ---------------------- Protected Sample Route ----------------------
@app.get("/api/chat/conversations")
def list_conversations(user=Depends(get_current_user)):
    # Minimal placeholder: return empty list initially
    items = list(db["conversations"].find({"user_id": user["user_id"]}).sort("updated_at", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
    return {"success": True, "conversations": items}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
