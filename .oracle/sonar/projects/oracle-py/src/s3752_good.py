app.add_route("GET", handle_readings)
app.route("/readings", methods=["GET", "POST"])
app.add_url_rule("/summary", view_summary, methods=["GET"])
