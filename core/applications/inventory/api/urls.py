from django.contrib import admin
from django.urls import path, include

from core.applications.inventory import api
from core.applications.inventory.api.views import asset_register, supplier_register, class_register, category_register, \
    get_tag, get_serial, transfer_register
from core.applications.inventory.views import index, register

app_name = "api"
urlpatterns = [
    path("register/", asset_register, name="register"),
    path("transfer/", transfer_register, name="transfer"),
    path("supplier-register/", supplier_register, name="supplier-register"),
    path("class-register/", class_register, name="class-register"),
    path("category-register/", category_register, name="category-register"),
    path("get-tag/<str:tag>/", get_tag, name="tag"),
    path("get-serial/<str:serial>/", get_serial, name="serial"),
]
