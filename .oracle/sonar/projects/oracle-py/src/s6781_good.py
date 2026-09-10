import os
import jwt

token = jwt.encode({"sub": "example-user"}, os.environ["JWT_SIGNING_KEY"], algorithm="HS256")
