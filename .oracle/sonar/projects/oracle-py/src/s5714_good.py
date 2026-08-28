try:
    parse()
except (ValueError, KeyError):
    recover()
