"""Module docstring."""
value = 9
"attribute text"
value
value << 1
value >> 1
value | 1
value & 1
value ^ 1
value + 1
(value | 1) + 1
1 + (value << 1)
[(value >> 1)]
not (value | 1)
(value | 1) > 1
(value | 1) and False
class EllipsisDummy: ...

def ext():
    """Function docstring."""
    "work note"
    value
    value << 1
    value >> 1
    value | 1
    value + 1
    print(value | 1)
...

class Placeholder:
    ...

class HasValue:
    answer = 42
    ...

def stub():
    ...

def not_stub():
    n = 42
    ...

if value:
    ...
