render(req, "list.html", locals())


def detail(req):
    return render(req, "detail.html", locals())
