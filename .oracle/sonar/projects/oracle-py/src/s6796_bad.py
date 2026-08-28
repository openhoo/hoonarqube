from typing import TypeVar

T = TypeVar("T")

def identity(item: T) -> T:
    return item
