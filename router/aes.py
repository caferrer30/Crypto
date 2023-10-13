import os
import base64
import binascii
from fastapi import APIRouter, HTTPException, status
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pydantic import BaseModel

class ENCRYPT(BaseModel):
    data: str
    iv: str
    mode: str
    size: int
    padding: bool

class DECRYPT(BaseModel):
    dataencrypt: str
    dkey: str
    iv: str
    mode: str
    padding: bool
    tag: str

class KCV(BaseModel):
    dkey: str
    input_codec: str

router = APIRouter()

#ENCRYPT-------------------------------------------------------------------------------------------------------------------------------

@router.post("/aes/encrypt")
async def encrypt(encrypt: ENCRYPT, response_model=ENCRYPT, status_code=status.HTTP_200_OK):
    if encrypt.padding:
        BLOCK_SIZE = 16
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
        data_pad = pad(encrypt.data)
        data_bytes = data_pad.encode()
    else:
        data_bytes = encrypt.data.encode()
#Key_Size
    if encrypt.size == 128:
        key = os.urandom(16)
    elif encrypt.size == 192:
        key = os.urandom(24)
    elif encrypt.size == 256:
        key = os.urandom(32)
    else:
        status_code=status.HTTP_400_BAD_REQUEST
#Key a B64
    dkey = base64.b64encode(key)
    iv = encrypt.iv.encode()
#MODE
    if encrypt.mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif encrypt.mode == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    else:
        status_code=status.HTTP_400_BAD_REQUEST
 #Cifrado
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    dataencrypt = base64.b64encode(ct)
    if encrypt.mode == "GCM":
        tag = base64.b64encode(encryptor.tag)
    else:
        tag = ""
    return {"dataencrypt": dataencrypt, "dkey": dkey, "iv": encrypt.iv, "mode" : encrypt.mode, "padding": encrypt.padding, "tag": tag}

#DECRYPT-------------------------------------------------------------------------------------------------------------------------------

@router.post("/aes/decrypt")
async def decrypt(decrypt: DECRYPT, response_model=DECRYPT, status_code=status.HTTP_200_OK):
#Key a B64
    key = base64.b64decode(decrypt.dkey)
    iv = decrypt.iv.encode()
    data_bytes = base64.b64decode(decrypt.dataencrypt)
    tag = base64.b64decode(decrypt.tag)
#MODE
    if decrypt.mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif decrypt.mode == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    else:
        status_code=status.HTTP_400_BAD_REQUEST
 #Cifrado
    decryptor = cipher.decryptor()
    ct = decryptor.update(data_bytes) + decryptor.finalize()
    datadecrypt = ct.decode()
    if decrypt.padding:
        unpad = lambda s : s[0:-ord(s[-1])]
        data_unpad = unpad(datadecrypt)
    else:
        data_unpad = datadecrypt
    return {"data": data_unpad}

#KCV--------------------------------------------------------------------------------------------------------------------------

@router.post("/aes/kcv")
async def kcv(kcv: KCV, response_model=KCV, status_code=status.HTTP_200_OK):
    if kcv.input_codec == "B64":
        key = base64.b64decode(kcv.dkey)
        dkey = base64.b64decode(kcv.dkey).hex()
    elif kcv.input_codec == "HEX":       
        key = bytes.fromhex(kcv.dkey)
    else:
        status_code=status.HTTP_400_BAD_REQUEST       
    data_bytes = "0000000000000000".encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
 #Cifrado
    encryptor = cipher.encryptor()
    ct = encryptor.update(data_bytes) + encryptor.finalize()
    kcv_hex = base64.b64encode(ct).hex()[0:6]
    return {"kcv": kcv_hex}
    #return {"key" : key}



