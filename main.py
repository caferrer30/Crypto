from fastapi import FastAPI
from router import pwdgen, signup, fernet, aes

#API
app = FastAPI()

#Routers
app.include_router(pwdgen.router)
app.include_router(signup.router)
app.include_router(fernet.router)
app.include_router(aes.router) 
