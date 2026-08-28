app.add_route("*", handle_everything)
app.route("/everything", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
app.add_url_rule("/all", view_all, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
