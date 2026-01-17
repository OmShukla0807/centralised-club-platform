from datetime import datetime, timedelta,timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
# checkig wheter security error is non empty or not!!
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set")

# --- THE HASHER ---
# This object handles the encryption logic using "bcrypt" (industry standard)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 1. HASHING FUNCTION
# Input: "secret123" -> Output: "$2b$12$EixZa..."
def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# 2. VERIFICATION FUNCTION
# Checks if the plain password matches the hash stored in DB
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# 3. TOKEN GENERATOR 
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    
    # Add 'exp' (Expiration) claim to the token
    to_encode.update({"exp": expire})
    
    # Create the encoded JWT string
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt