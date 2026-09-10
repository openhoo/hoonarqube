from django.http import HttpResponse
from django.views.decorators.http import require_GET, require_POST, require_http_methods

@require_GET
def view(request):
    return HttpResponse("read")

@require_POST
def second_view(request):
    return HttpResponse("write")

@require_http_methods(["HEAD"])
def third_view(request):
    return HttpResponse("headers")
