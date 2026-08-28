def handle():
    try:
        risky()
    except ValueError:
        log(error)
        raise
    except KeyError:
        return None
