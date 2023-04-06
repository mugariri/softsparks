from django.urls import path, include

from core.applications.company.views import user_login, user_logout

app_name = 'company'

urlpatterns = [
    path('login', user_login, name='login'),
    path('logout', user_logout, name='logout'),

]
