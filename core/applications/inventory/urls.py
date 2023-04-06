
from django.contrib import admin
from django.urls import path, include

from core.applications.inventory import api
from core.applications.inventory.views import index, register, transfer

app_name = "inventory"
urlpatterns = [
    path("index/", index, name="index"),
    path("register/", register, name="register"),
    path("transfer/", transfer, name="transfer"),
    path("api/", include('core.applications.inventory.api.urls', namespace='api'), name="api"),
]
