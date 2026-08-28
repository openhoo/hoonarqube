class AppError(Exception):
    pass
class NotFound(AppError):
    pass
try:
    work()
except (NotFound, AppError):
    recover()
