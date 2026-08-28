from typing import Union

alias = Union[int, str]

def parse(raw: int | str) -> int:
    return int(raw)
