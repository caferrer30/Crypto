import os
import time
import base64
from fastapi import APIRouter, HTTPException, status
from cryptography.hazmat.primitives.twofactor.totp import TOTP
from cryptography.hazmat.primitives.hashes import SHA1, SHA256
from pydantic import BaseModel

class OTP(BaseModel):
    key: str
    otp: str
    time: float

router = APIRouter()    

@router.get("/totp/generate")
async def totp(otp: OTP, response_model=OTP, status_code=status.HTTP_200_OK):
    key = os.urandom(20)
    dkey = base64.b64encode(key)
    totp = TOTP(key, 8, SHA1(), 30)
    time_value = time.time()
    totp_value = totp.generate(time_value)
    verify = totp.verify(totp_value, time_value)
    return {"key" : dkey, "otp": totp_value, "time" : time_value}

@router.get("/totp/verify")
async def totp(otp: OTP, response_model=OTP, status_code=status.HTTP_200_OK):
    totp_value = otp.otp.encode()
    key = base64.b64decode(otp.key)
    totp = TOTP(key, 8, SHA1(), 30)
    time_value = otp.time
    verify = totp.verify(totp_value, time_value)
    return {"verify": verify}