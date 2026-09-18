import secrets


password = 'hunter2'
set_password = 'ALTER USER %(user)s IDENTIFIED BY "%(password)s"'
token = secrets.token_hex(32)
