from fastapi import APIRouter, HTTPException, status
from db.models.user import User
from db.client_db import db_client
from db.schemas.user import user_schema
import secrets, string

router = APIRouter()

@router.post("/signup", response_model=User, status_code=status.HTTP_201_CREATED)
async def signup(user: User):
    user_dict = dict(user)
    if not user_dict["pwd"]:
        alphabet = string.ascii_letters + string.digits
        pwd_length = 12
        pwdgen = ''
        for i in range(pwd_length):
            pwdgen += ''.join(secrets.choice(alphabet))
        user_dict["pwd"] = pwdgen
        del user_dict["id"]
        id = db_client.local.users.insert_one(user_dict).inserted_id
        new_user = user_schema(db_client.local.users.find_one({"_id" : id}))
    else:
        del user_dict["id"]
        id = db_client.local.users.insert_one(user_dict).inserted_id
        new_user = user_schema(db_client.local.users.find_one({"_id" : id}))
        new_user["pwd"] = ""
    return User(**new_user)



