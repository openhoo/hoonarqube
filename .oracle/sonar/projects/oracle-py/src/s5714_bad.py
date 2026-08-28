try:
    parse()
except (ValueError and KeyError):
    recover()
