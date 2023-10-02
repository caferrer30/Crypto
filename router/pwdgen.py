from fastapi import APIRouter
from pydantic import BaseModel
import secrets, string

class PWD(BaseModel):
    length: int
    flag_letter: bool
    flag_digits: bool
    flag_punctuation: bool

router = APIRouter()


@router.get("/pwd/gen1")
async def password(password: PWD):
    letters = ""
    digits = ""
    punctuation = ""
    if password.flag_letter:
        letters = string.ascii_letters 
    if password.flag_digits:
        digits = string.digits
    if password.flag_punctuation:
        punctuation = string.punctuation
    alphabet = letters + digits + punctuation
    pwd_length = password.length
    pwd = ''
    for i in range(pwd_length):
        pwd += ''.join(secrets.choice(alphabet))
    return {"password": pwd}

