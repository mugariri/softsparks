from django.contrib import admin
from django.urls import path, include

app_name = 'applications'

urlpatterns = [
    path("inventory/", include('core.applications.inventory.urls', namespace='inventory'), name='inventory'),
    path("inventory/authentications/", include('core.applications.company.urls', namespace='company'), name='company'),
]
