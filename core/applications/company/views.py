from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect


# Create your views here.
def user_login(request):
    template = 'auth/login.html'
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("applications:inventory:index")
        else:
            messages.success(request, "incorrect username or password")
            return redirect('applications:company:login')

    context = {}
    return render(request, template, context=context)


def user_logout(request):
    logout(request)
    return redirect('applications:company:login')
