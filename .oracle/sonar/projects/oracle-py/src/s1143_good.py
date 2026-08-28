def load_data():
    try:
        load()
    finally:
        release()
    return 1
