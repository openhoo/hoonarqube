def run_app():
    return 1

def cleanup():
    return 2

def main():
    try:
        run_app()
    except SystemExit:
        cleanup()
        raise
