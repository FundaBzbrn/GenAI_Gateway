"""
GenAI Security Gateway - Kimlik Doğrulama Kontrolcüsü (Auth Controller)

Sisteme giriş yapan kullanıcıların kimlik doğrulamasını (Authentication) ve 
yetkilendirmesini (Authorization) sağlar. 
Kullanıcı giriş yaptığında bir JWT (JSON Web Token) üretilir ve bu token 
diğer tüm korumalı uç noktalarda (endpoints) güvenliği sağlamak için kullanılır.
Ayrıca profil güncelleme ve şifre değiştirme işlemleri de bu dosyada bulunur.
"""

from fastapi import APIRouter, HTTPException, Security, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional
from passlib.context import CryptContext
import jwt
import datetime
import os
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from app.services.database_manager import DatabaseManager

router = APIRouter()
security = HTTPBearer()

# OAuth Config
config = Config('.env')
oauth = OAuth(config)

# Configure Google
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID', ''),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET', ''),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# Configure Github
oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_CLIENT_ID', ''),
    client_secret=os.getenv('GITHUB_CLIENT_SECRET', ''),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Password hashing config
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT config
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-genai-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 1 day

class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    phone: Optional[str] = None
    full_name: str = ""
    company_id: Optional[int] = None
    role: str = "employee"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    phone: Optional[str] = None
    full_name: Optional[str] = None
    profile_photo: Optional[str] = None

class PasswordUpdate(BaseModel):
    old_password: str
    new_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def verify_admin(payload: dict = Depends(verify_token)):
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return payload

@router.post("/register", tags=["Auth"])
async def register(user: UserRegister):
    existing_user = await DatabaseManager.get_user_by_username(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    # Varsayılan rol "user" olarak ayarlanmıştır
    success = await DatabaseManager.create_user(
        username=user.username, 
        password_hash=hashed_password,
        email=user.email,
        phone=user.phone,
        full_name=user.full_name,
        role=user.role,
        company_id=user.company_id
    )
    if not success:
        raise HTTPException(status_code=500, detail="Error creating user")
        
    return {"message": "User created successfully. You can now login."}

@router.post("/login", tags=["Auth"])
async def login(user: UserLogin):
    db_user = await DatabaseManager.get_user_by_username(user.username)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    match = verify_password(user.password, db_user["password_hash"])
    if not match:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    access_token = create_access_token(
        data={
            "sub": user.username, 
            "role": db_user.get("role", "employee"),
            "company_id": db_user.get("company_id")
        }
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "username": user.username,
        "role": db_user.get("role", "employee"),
        "company_id": db_user.get("company_id"),
        "full_name": db_user.get("full_name", ""),
        "profile_photo": db_user.get("profile_photo", "")
    }

@router.get("/me", tags=["Auth"])
async def get_my_profile(payload: dict = Depends(verify_token)):
    username = payload.get("sub")
    db_user = await DatabaseManager.get_user_by_username(username)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "username": db_user["username"],
        "email": db_user.get("email"),
        "phone": db_user.get("phone"),
        "full_name": db_user.get("full_name"),
        "role": db_user.get("role"),
        "company_id": db_user.get("company_id"),
        "profile_photo": db_user.get("profile_photo")
    }

@router.put("/me", tags=["Auth"])
async def update_my_profile(profile_data: UserUpdate, payload: dict = Depends(verify_token)):
    username = payload.get("sub")
    update_dict = profile_data.dict(exclude_unset=True)
    if not update_dict:
        return {"message": "No data provided to update"}
        
    success = await DatabaseManager.update_user_profile(username, update_dict)
    if not success:
        raise HTTPException(status_code=500, detail="Error updating profile")
    return {"message": "Profile updated successfully"}

@router.put("/me/password", tags=["Auth"])
async def update_my_password(pwd_data: PasswordUpdate, payload: dict = Depends(verify_token)):
    username = payload.get("sub")
    db_user = await DatabaseManager.get_user_by_username(username)
    
    if not verify_password(pwd_data.old_password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Exiting password is incorrect")
        
    new_hash = get_password_hash(pwd_data.new_password)
    success = await DatabaseManager.update_user_password(username, new_hash)
    if not success:
        raise HTTPException(status_code=500, detail="Error updating password")
    return {"message": "Password updated successfully"}

# --- OAUTH ENDPOINTS ---
@router.get("/login/google", tags=["Auth"])
async def login_google(request: Request):
    if not os.getenv('GOOGLE_CLIENT_ID'):
        raise HTTPException(status_code=500, detail="Google OAuth is not configured in .env")
    redirect_uri = request.url_for('auth_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/callback/google", tags=["Auth"])
async def auth_google(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        userinfo = token.get('userinfo')
        if not userinfo:
            userinfo = await oauth.google.userinfo(token=token)
            
        # Check if user exists
        email = userinfo.get('email')
        db_user = await DatabaseManager.get_user_by_username(email)
        
        if not db_user:
            # Create user
            await DatabaseManager.create_user(
                username=email,
                password_hash=get_password_hash("oauth_default_pass_123"), # Social users use oauth
                email=email,
                full_name=userinfo.get('name', ''),
                profile_photo=userinfo.get('picture', ''),
                role="employee"
            )
            db_user = await DatabaseManager.get_user_by_username(email)
            
        access_token = create_access_token(
            data={
                "sub": db_user["username"], 
                "role": db_user.get("role", "employee"),
                "company_id": db_user.get("company_id")
            }
        )
        # Ideally, redirect to frontend with token in URL or set a cookie.
        # Since it's API, we'll return a simple HTML that posts message to parent window.
        html_content = f"""
        <html><body><script>
        window.opener.postMessage({{
            token: '{access_token}', 
            role: '{db_user.get("role")}',
            type: 'oauth_success'
        }}, '*');
        window.close();
        </script></body></html>
        """
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/login/github", tags=["Auth"])
async def login_github(request: Request):
    if not os.getenv('GITHUB_CLIENT_ID'):
        raise HTTPException(status_code=500, detail="Github OAuth is not configured in .env")
    redirect_uri = request.url_for('auth_github')
    return await oauth.github.authorize_redirect(request, redirect_uri)

@router.get("/callback/github", tags=["Auth"])
async def auth_github(request: Request):
    try:
        token = await oauth.github.authorize_access_token(request)
        resp = await oauth.github.get('user', token=token)
        userinfo = resp.json()
        
        username = f"github_{userinfo.get('login')}"
        email = userinfo.get('email')
        
        db_user = await DatabaseManager.get_user_by_username(username)
        
        if not db_user:
            await DatabaseManager.create_user(
                username=username,
                password_hash=get_password_hash("oauth_default_pass_123"),
                email=email,
                full_name=userinfo.get('name', ''),
                profile_photo=userinfo.get('avatar_url', ''),
                role="employee"
            )
            db_user = await DatabaseManager.get_user_by_username(username)
            
        access_token = create_access_token(
            data={
                "sub": db_user["username"], 
                "role": db_user.get("role", "employee"),
                "company_id": db_user.get("company_id")
            }
        )
        html_content = f"""
        <html><body><script>
        window.opener.postMessage({{
            token: '{access_token}', 
            role: '{db_user.get("role")}',
            type: 'oauth_success'
        }}, '*');
        window.close();
        </script></body></html>
        """
        from fastapi.responses import HTMLResponse
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
