from django.http import HttpResponse

def view(request):
    return HttpResponse("first unrestricted view")

def second_view(request):
    return HttpResponse("second unrestricted view")

def third_view(request):
    return HttpResponse("third unrestricted view")
