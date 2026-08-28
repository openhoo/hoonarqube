@app.get("/health")
def health_handler():
    return "ok"


@app.route("/about")
def about_handler():
    return "about"
