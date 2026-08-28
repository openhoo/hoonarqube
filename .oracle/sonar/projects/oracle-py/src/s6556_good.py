render(req, "list.html", {"items": items})


def detail(req):
    return render(req, "detail.html", {"item": item})
