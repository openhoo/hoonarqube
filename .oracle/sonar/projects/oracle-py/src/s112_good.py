class OperationError(Exception):
    pass


def fail_with_specific_exception():
    raise OperationError("operation failed")
