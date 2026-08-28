@app.get("/items")
@log_call
def items_handler():
    return []


@app.post("/items")
@require_admin
def create_handler():
    return {}
