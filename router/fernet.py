from fastapi import APIRouter, HTTPException, status
from cryptography.fernet import Fernet
from pydantic import BaseModel

class ENCRYPT(BaseModel):
    data: str

class DECRYPT(BaseModel):
    dataencrypt: str
    dkey: str

router = APIRouter()

@router.get("/fernet/encrypt", response_model=ENCRYPT, status_code=status.HTTP_200_OK)
async def encrypt(encrypt: ENCRYPT):
    # key is generated
    key = Fernet.generate_key()
    # value of key is assigned to a variable
    f = Fernet(key)
    # the plaintext is converted to ciphertext
    bytes_data = encrypt.data
    bytes = bytes_data.encode()
    data_encrypt = f.encrypt(bytes)
    return {"dataencrypt": data_encrypt, "dkey": key}

@router.get("/fernet/decrypt",response_model=ENCRYPT, status_code=status.HTTP_200_OK)
async def decrypt(decrypt: DECRYPT):
    # key is generated
    key = decrypt.dkey
    # value of key is assigned to a variable
    f = Fernet(key)
    # the plaintext is converted to ciphertext
    bytes_data = decrypt.dataencrypt
    bytes = bytes_data.encode()
    data_decrypt = f.decrypt(bytes)
    return {"data": data_decrypt}

