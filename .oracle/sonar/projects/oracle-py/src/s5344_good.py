import secrets


password = 'hunter2'
set_password = 'ALTER USER %s IDENTIFIED BY %s'
token = secrets.token_hex(32)
